#!/usr/bin/python3
"""Map an API from how it answers: sibling routes of the same shape, methods it
honours versus rejects, and objects in responses that name routes nobody documented."""
import json
import re
import sys
from urllib.parse import urlparse

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

WORDS = ["users", "user", "exports", "export", "accounts", "roles", "tokens", "keys",
         "sessions", "orders", "bookings", "invoices", "logs", "audit", "config",
         "settings", "health", "status", "me", "admin"]
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
REJECTED = (405, 501)


def methods_for(url):
    honoured, rejected = [], []
    for method in METHODS:
        r = http(url, method=method)
        if r is None:
            continue
        if r.status_code in REJECTED:
            rejected.append(method)
        elif r.status_code != 404:
            honoured.append(method)
    return honoured, rejected


def routes_in(payload, prefix):
    found = set()
    try:
        blob = json.dumps(payload)
    except (TypeError, ValueError):
        return found
    for hit in re.findall(rf'({re.escape(prefix)}/[A-Za-z0-9_\-/]+)', blob):
        found.add(hit.rstrip("/"))
    return found


def main():
    if len(sys.argv) < 2:
        print("Usage: ./6-api_mapper.py <api_base_url> [wordlist]")
        return 1
    api_base = sys.argv[1].rstrip("/")
    words = WORDS
    if len(sys.argv) > 2:
        with open(sys.argv[2]) as fh:
            words = [line.strip() for line in fh if line.strip()]

    parsed = urlparse(api_base)
    prefix = parsed.path.rstrip("/")
    root = f"{parsed.scheme}://{parsed.netloc}"

    known = f"{prefix}/internal/exports"
    queue = [known] + [f"{prefix}/internal/{w}" for w in words]
    seen, mapped = set(), {}

    while queue:
        route = queue.pop(0)
        if route in seen:
            continue
        seen.add(route)
        url = root + route
        r = http(url)
        if r is None or r.status_code in (401, 403, 404, 410) or r.status_code >= 500:
            continue
        honoured, rejected = methods_for(url)
        if not honoured:
            continue
        mapped[route] = (honoured, rejected, route != known)
        if "json" in r.headers.get("Content-Type", ""):
            try:
                for extra in routes_in(json.loads(r.text), prefix):
                    if extra not in seen:
                        queue.append(extra)
            except ValueError:
                pass

    for route, (honoured, rejected, undocumented) in sorted(mapped.items()):
        tag = "   (undocumented)" if undocumented else ""
        print(f"[+] {route:<30} {', '.join(honoured):<14} rejects {', '.join(rejected) or '-'}{tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
