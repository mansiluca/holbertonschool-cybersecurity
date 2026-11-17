#!/usr/bin/python3
"""Walk the layers end to end: forgotten host name -> JavaScript -> API -> parameter.

The chain reuses the reasoning of the five tools: find_vhost reproduces
3-vhost_finder, js_endpoint reproduces 4-js_recon, api_route reproduces
6-api_mapper and find_param reproduces 7-param_finder. Each step consumes the
result of the previous one and stops if that result is missing, so a chain that
skips a link cannot report a confirmation. Confirms the misconfiguration is
present and stops there; leveraging is the next phase."""
import re
import sys
import uuid

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

DOMAIN = "driftwood.example"
VHOSTS = ["admin-dev", "admin", "dev", "internal", "staging"]
IGNORED = uuid.uuid4().hex[:8]


def find_vhost():
    """A vhost exists only if its answer differs from the catch-all."""
    catch = http(f"http://{DOMAIN}/", headers={"Host": f"nope-{IGNORED}.{DOMAIN}",
                                             "User-Agent": "ridgeline-enum/1.0"})
    for name in VHOSTS:
        host = f"{name}.{DOMAIN}"
        r = http(f"http://{host}/", headers={"Host": host, "User-Agent": "ridgeline-enum/1.0"})
        if r is None or r.status_code >= 500:
            continue
        if catch is None or r.status_code != catch.status_code or abs(len(r.text) - len(catch.text)) > 50:
            return host
    return None


def js_endpoint(vhost):
    """Mine the bundles for a route, including the lazy chunks nobody loads."""
    page = http(f"http://{vhost}/")
    if page is None:
        return None
    chunks = [c if c.startswith("http") else f"http://{vhost}/{c.lstrip('/')}"
              for c in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', page.text, re.I)]
    for asset in list(chunks):
        body = http(asset)
        if body is None:
            continue
        for chunk in re.findall(r'["\'`]([A-Za-z0-9_\-.]+\.js)["\'`]', body.text):
            resolved = chunk if chunk.startswith("http") else f"http://{vhost}/{chunk.lstrip('/')}"
            if resolved not in chunks:
                chunks.append(resolved)
    for asset in chunks:
        body = http(asset)
        if body is None:
            continue
        for hit in re.findall(r'["\'`](/api/[A-Za-z0-9_\-/]+)["\'`]', body.text):
            if "internal" in hit:
                return hit
    return None


def api_route(vhost, endpoint):
    """The endpoint must answer and accept a method, otherwise the chain is broken."""
    r = http(f"http://{vhost}{endpoint}")
    return r is not None and r.status_code < 400


def find_param(vhost, endpoint):
    """An ignored parameter changes nothing; an honoured one changes the object."""
    url = f"http://{vhost}{endpoint}"
    def measure(query):
        r = http(f"{url}?{query}")
        if r is None:
            return None
        text = r.text
        for token in query.replace("=", " ").split():
            text = text.replace(token, "")
        return r.status_code, len(text)

    base = measure(f"ignored_{IGNORED}=1")
    if base is None:
        return None
    for candidate in ("role", "admin", "internal", "debug", "full", "scope"):
        current = measure(f"{candidate}=admin")
        if current is None:
            continue
        if current[0] != base[0] or abs(current[1] - base[1]) > 100:
            return candidate
    return None


def main():
    vhost = find_vhost()
    if not vhost:
        print("[-] no forgotten host answers by name, chain stops here")
        return 1
    print(f"[1] vhost  {vhost}")

    endpoint = js_endpoint(vhost)
    if not endpoint:
        print("[-] no route in the bundles, chain stops here")
        return 1
    print(f"[2] js     {endpoint}")

    if not api_route(vhost, endpoint):
        print(f"[-] {endpoint} does not answer, chain stops here")
        return 1

    param = find_param(vhost, endpoint)
    if not param:
        print("[-] no honoured parameter, chain stops here")
        return 1
    print(f"[3] param  {param}")
    print(f"[+] CONFIRMED: missing authorization on '{param}' (present, not exploited)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
