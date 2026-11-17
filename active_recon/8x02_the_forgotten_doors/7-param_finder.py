#!/usr/bin/python3
"""Find a hidden parameter by the change it causes, not by guessing it exists.

An ignored parameter leaves the response identical to a baseline built from an
impossible name: same status, same length, same timing band, same content. The
honoured one breaks at least one of those.
"""
import sys
import time
import uuid
from urllib.parse import urlencode

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

PARAMS = ["role", "admin", "debug", "internal", "verbose", "test", "dev", "export",
          "scope", "tenant", "user", "id", "format", "limit", "full", "fields"]


def call(url, params):
    """Normalise the echo: a server that reflects the query string must not look
    like a server that honored the parameter."""
    target = f"{url}{'&' if '?' in url else '?'}{urlencode(params)}"
    started = time.time()
    r = http(target)
    if r is None:
        return None
    text = r.text
    for key, value in params.items():
        text = text.replace(key, "").replace(str(value), "")
    return {"status": r.status_code, "len": len(text), "ms": int((time.time() - started) * 1000),
            "body": " ".join(text.lower().split())[:2000]}


def changed(current, base):
    if current is None:
        return None
    if current["status"] != base["status"]:
        return "status"
    if abs(current["len"] - base["len"]) > 100:
        return "length"
    if base["ms"] and current["ms"] > max(3 * base["ms"], base["ms"] + 800):
        return "timing"
    if current["body"] != base["body"]:
        return "content"
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: ./7-param_finder.py <url> [wordlist]")
        return 1
    url = sys.argv[1]
    params = PARAMS
    if len(sys.argv) > 2:
        with open(sys.argv[2]) as fh:
            params = [line.strip() for line in fh if line.strip()]

    ignored = f"ignored_{uuid.uuid4().hex[:8]}"
    base = call(url, {ignored: "test"})
    if base is None:
        print("[!] target does not answer", file=sys.stderr)
        return 1
    print(f"[*] baseline: {base['status']} len={base['len']}")

    for param in params:
        current = call(url, {param: "admin"})
        reason = changed(current, base)
        if not reason:
            continue
        print(f"[+] param '{param}'   {current['status']} len={current['len']}   (behavior change: {reason}, honored)")
        if current["status"] in (401, 403):
            print("    -> authorization-relevant, stop here")
        elif current["status"] >= 500:
            print("    -> injectable-looking, stop here")
        else:
            print("    -> changes the object returned, authorization-relevant, stop here")
        return 0
    print("[*] no honored parameter in the wordlist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
