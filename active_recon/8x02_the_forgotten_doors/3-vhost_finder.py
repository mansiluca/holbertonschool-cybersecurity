#!/usr/bin/python3
"""Virtual host finder: a name-based door is invisible until you ask for it by name.

Baseline the default page and the answer to a name the server never heard; any
other response that differs from both is a real host on the shared listener.
"""
import difflib
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

NAMES = ["admin", "admin-dev", "api", "dev", "internal", "intranet", "staging", "test",
         "beta", "portal", "backup", "git", "jenkins", "monitor", "vpn"]


def fetch(ip_url, host):
    try:
        return http(ip_url, headers={"Host": host, "User-Agent": "ridgeline-enum/1.0"})
    except Exception:
        return None


def signature(r):
    return (r.status_code, len(r.text), " ".join(r.text.lower().split())[:400])


def differs(r, refs):
    sig = signature(r)
    for ref in refs:
        if sig[0] == ref[0] and abs(sig[1] - ref[1]) < 30:
            return False
        if r.status_code == ref[0] and difflib.SequenceMatcher(None, sig[2], ref[2]).ratio() > 0.95:
            return False
    return True


def main():
    if len(sys.argv) < 3:
        print("Usage: ./3-vhost_finder.py <domain> <ip> [wordlist]")
        return 1
    domain = sys.argv[1]
    ip = sys.argv[2]
    names = NAMES
    if len(sys.argv) > 3:
        with open(sys.argv[3]) as fh:
            names = [line.strip() for line in fh if line.strip()]

    ip_url = f"http://{ip}/" if ":" in ip else f"http://{ip}:80/"
    unknown = f"{uuid.uuid4().hex[:10]}.{domain}"
    refs = []
    for host in (ip, unknown):
        r = fetch(ip_url, host)
        if r is not None:
            refs.append(signature(r))
    if not refs:
        print("[!] target does not answer", file=sys.stderr)
        return 1
    print(f"[*] baseline: {refs[0][0]} len={refs[0][1]}")
    print(f"[*] catch-all probe: {unknown} -> {refs[-1][0]} len={refs[-1][1]}")

    for name in names:
        host = f"{name}.{domain}"
        r = fetch(ip_url, host)
        if r is None or r.status_code >= 500:
            continue
        if differs(r, refs):
            print(f"[+] {host:<32} {r.status_code} len={len(r.text)}   (differs from baseline)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
