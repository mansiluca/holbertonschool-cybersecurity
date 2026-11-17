#!/usr/bin/python3
"""Mine the front end for the back end it forgot to hide.

Fetches every script tag and every chunk those scripts reference, extracts routes
across several patterns, resolves them against the base and deduplicates.
"""
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


def http(url, headers=None, method="GET", timeout=6):
    req = urllib.request.Request(url, method=method,
                                 headers=headers or {"User-Agent": "ridgeline-enum/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return Response(r.status, dict(r.headers), r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return Response(exc.code, dict(exc.headers or {}), exc.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None

ROUTE_PATTERNS = [
    re.compile(r'["\'`](/(?:api|v\d)/[A-Za-z0-9_\-/{}$.:]+)["\'`]'),
    re.compile(r'["\'`](/[A-Za-z0-9_\-]{3,}/[A-Za-z0-9_\-.]+)["\'`]'),
    re.compile(r'(?:fetch|axios(?:\.\w+)?)\s*\(\s*["\'`]([^"\'`]+)["\'`]'),
    re.compile(r'["\'`]([a-z0-9.\-]*\.driftwood\.example[^"\'`]*)["\'`]'),
]
KEY_PATTERNS = [
    re.compile(r'(AKIA[0-9A-Z]{16})'),
    re.compile(r'(sk_live_[A-Za-z0-9]{10,})'),
    re.compile(r'(?:api[_-]?key|secret|token)["\'`]?\s*[:=]\s*["\'`]([A-Za-z0-9_\-]{16,})["\'`]', re.I),
]
CHUNK_PATTERN = re.compile(r'["\'`]([A-Za-z0-9_\-.]+\.[a-z0-9]+js?)["\'`]')
SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


def fetch(url):
    r = http(url)
    return r.text if r is not None and r.status_code == 200 else ""


def main():
    if len(sys.argv) < 2:
        print("Usage: ./4-js_recon.py <base_url>")
        return 1
    base_url = sys.argv[1].rstrip("/")
    html = fetch(base_url)
    if not html:
        print("[!] cannot read the target", file=sys.stderr)
        return 1

    queue = [urljoin(base_url + "/", src) for src in SCRIPT_SRC.findall(html)]
    seen_assets, endpoints, keys = set(), {}, {}

    while queue:
        asset = queue.pop(0)
        if asset in seen_assets:
            continue
        seen_assets.add(asset)
        body = fetch(asset)
        if not body:
            continue
        name = urlparse(asset).path.rsplit("/", 1)[-1]

        for pattern in ROUTE_PATTERNS:
            for hit in pattern.findall(body):
                endpoints.setdefault(hit, name)

        for pattern in KEY_PATTERNS:
            for hit in pattern.findall(body):
                keys.setdefault(hit, name)

        for chunk in CHUNK_PATTERN.findall(body):
            candidate = urljoin(asset, chunk)
            if candidate not in seen_assets:
                queue.append(candidate)

    for route, source in sorted(endpoints.items()):
        print(f"[+] endpoint  {route:<30} (found in {source})")
    for key, source in sorted(keys.items()):
        print(f"[+] key       {key:<30} (hardcoded in {source})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
