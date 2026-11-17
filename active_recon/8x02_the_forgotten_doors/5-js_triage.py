#!/usr/bin/python3
"""Triage what the analyzer extracted: internal surface versus external noise and
fossils. A route that answers gone is not a finding."""
import re
import sys
from urllib.parse import urljoin, urlparse

import urllib.error
import urllib.parse
import urllib.request


class Response:
    """Minimal stand-in for a requests response: the lab box has no requests module."""

    def __init__(self, status, headers, text):
        self.status_code = status
        self.headers = headers
        self.text = text


try:
    import requests
except ImportError:  # the lab box ships without it
    requests = None


def http(url, headers=None, method="GET", timeout=6):
    if requests is not None:
        try:
            if method == "GET":
                r = requests.get(url, headers=headers or {"User-Agent": "ridgeline-enum/1.0"},
                                 timeout=timeout, allow_redirects=False)
            else:
                r = requests.request(method, url, headers=headers or {"User-Agent": "ridgeline-enum/1.0"},
                                     timeout=timeout)
            return Response(r.status_code, dict(r.headers), r.text)
        except Exception:
            return None
    req = urllib.request.Request(url, method=method,
                                 headers=headers or {"User-Agent": "ridgeline-enum/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return Response(r.status, dict(r.headers), r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return Response(exc.code, dict(exc.headers or {}), exc.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None

NOISE = ("cdn.", "analytics", "googletagmanager", "google-analytics", "facebook", "twitter",
         "linkedin", "fonts.", "jsdelivr", "unpkg", "cloudflare", "doubleclick", "hotjar")
PATH_PATTERN = re.compile(r'["\'`](/[A-Za-z0-9_\-/]{4,})["\'`]')
HOST_PATTERN = re.compile(r'(?:https?://)?([a-z0-9.\-]+\.driftwood\.example)')
CHUNK_PATTERN = re.compile(r'["\'`]([A-Za-z0-9_\-.]+\.js)["\'`]')
SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
ASSET_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".map")


def fetch(url):
    r = http(url)
    return r.text if r is not None and r.status_code == 200 else ""


def main():
    if len(sys.argv) < 2:
        print("Usage: ./5-js_triage.py <base_url>")
        return 1
    base_url = sys.argv[1].rstrip("/")
    html = fetch(base_url)
    if not html:
        print("[!] cannot read the target", file=sys.stderr)
        return 1

    queue = [urljoin(base_url + "/", src) for src in SCRIPT_SRC.findall(html)]
    seen, paths, hosts = set(), set(), set()
    while queue:
        asset = queue.pop(0)
        if asset in seen:
            continue
        seen.add(asset)
        body = fetch(asset)
        if not body:
            continue
        for p in PATH_PATTERN.findall(body):
            if not p.endswith(ASSET_EXT):
                paths.add(p)
        for h in HOST_PATTERN.findall(body):
            hosts.add(h)
        for chunk in CHUNK_PATTERN.findall(body):
            cand = urljoin(asset, chunk)
            if cand not in seen:
                queue.append(cand)

    live, dead = [], []
    for name in sorted(hosts):
        if any(n in name for n in NOISE):
            continue
        target = name if name.startswith("http") else f"http://{name}/"
        r = http(target)
        if r is None:
            dead.append(f"[dead]  {name:<30} no answer")
        elif r.status_code in (404, 410):
            dead.append(f"[dead]  {name:<30} {r.status_code} gone fossil")
        else:
            live.append(f"[live]  internal hostname: {name}")

    for path in sorted(paths):
        if any(n in path for n in NOISE):
            continue
        r = http(urljoin(base_url + "/", path))
        if r is None:
            continue
        if r.status_code in (404, 410):
            dead.append(f"[dead]  {path:<30} {r.status_code} gone fossil")
        elif r.status_code < 400:
            live.append(f"[live]  endpoint: {path}")

    for line in sorted(live):
        print(line)
    for line in sorted(dead):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
