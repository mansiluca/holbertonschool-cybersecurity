#!/usr/bin/python3
"""Content discovery that reasons about responses instead of trusting status codes.

The server answers every unknown path with 200 and a page-not-found body, so a
wordlist walk alone reports the whole tree. We baseline that lie, then keep only
the responses that break its signature.
"""
import hashlib
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

WORDS = [
    "admin", "administrator", "api", "assets", "backup", "backups", "blog", "config",
    "css", "dashboard", "dev", "docs", "files", "images", "img", "includes", "internal",
    "js", "login", "logs", "old", "partner-portal", "portal", "private", "public",
    "staging", "static", "test", "tmp", "uploads", "vendor",
]


def fingerprint(body):
    """Normalise a soft-404 body: the reflected path must not change the hash."""
    text = " ".join(body.lower().split())
    for marker in ("not found", "no such", "404", "error"):
        if marker in text:
            text = marker
            break
    return hashlib.md5(text.encode()).hexdigest()


def probe(url):
    try:
        return http(url)
    except Exception:
        return None


def baseline(base_url):
    """Three impossible paths; the signature is what they agree on."""
    samples = []
    for _ in range(3):
        r = probe(f"{base_url}/{uuid.uuid4().hex}")
        if r is not None:
            samples.append((r.status_code, len(r.text), fingerprint(r.text)))
    if not samples:
        return None
    status = max({s[0] for s in samples}, key=[s[0] for s in samples].count)
    length = max({s[1] for s in samples}, key=[s[1] for s in samples].count)
    fp = max({s[2] for s in samples}, key=[s[2] for s in samples].count)
    body = probe(f"{base_url}/{uuid.uuid4().hex}")
    marker = ""
    if body is not None:
        low = " ".join(body.text.lower().split())
        for cand in ("page not found", "not found", "no such file", "404"):
            if cand in low:
                marker = cand
                break
    return {"status": status, "length": length, "fp": fp, "marker": marker}


def breaks_signature(response, sig):
    if response.status_code != sig["status"]:
        return True
    if fingerprint(response.text) != sig["fp"]:
        return True
    return abs(len(response.text) - sig["length"]) > 200


def main():
    if len(sys.argv) < 2:
        print("Usage: ./1-discovery_engine.py <base_url> [wordlist]")
        return 1
    base_url = sys.argv[1].rstrip("/")
    words = WORDS
    if len(sys.argv) > 2:
        with open(sys.argv[2]) as fh:
            words = [line.strip() for line in fh if line.strip()]

    sig = baseline(base_url)
    if sig is None:
        print("[!] target does not answer", file=sys.stderr)
        return 1
    print(f'[*] soft-404 signature: {sig["status"]} len={sig["length"]} fp="{sig["marker"]}"')

    for word in words:
        url = f"{base_url}/{word}"
        r = probe(url)
        if r is None or r.status_code >= 500:
            continue
        if breaks_signature(r, sig):
            print(f"[+] /{word:<20} {r.status_code} len={len(r.text)}  (breaks signature)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
