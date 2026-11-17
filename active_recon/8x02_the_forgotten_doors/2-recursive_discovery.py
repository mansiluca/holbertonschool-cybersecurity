#!/usr/bin/python3
"""Recursive content discovery: carry the not-found baseline down every level and
infer extensions from the technology the responses reveal."""
import hashlib
import sys
import uuid
from collections import deque

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

WORDS = ["admin", "api", "assets", "backup", "config", "data", "docs", "files", "images",
         "includes", "internal", "js", "logs", "old", "private", "static", "tmp", "uploads"]
UNIVERSAL = [".bak", ".txt", ".old", ".zip"]
TECH_EXT = {
    "php": [".php", ".inc"],
    "express": [".js", ".json"],
    "node": [".js", ".json"],
    "python": [".py"],
    "nginx": [".html", ".conf"],
    "apache": [".html", ".htaccess"],
    "iis": [".aspx"],
    "tomcat": [".jsp"],
}


def fingerprint(body):
    text = " ".join(body.lower().split())
    for marker in ("not found", "no such", "404", "error"):
        if marker in text:
            return hashlib.md5(marker.encode()).hexdigest()
    return hashlib.md5(text.encode()).hexdigest()


def probe(url):
    try:
        return http(url)
    except Exception:
        return None


def baseline(base_url):
    samples = []
    for _ in range(2):
        r = probe(f"{base_url}/{uuid.uuid4().hex}")
        if r is not None:
            samples.append((r.status_code, len(r.text), fingerprint(r.text), r.headers))
    if not samples:
        return None
    status, length, fp, headers = samples[0]
    return {"status": status, "length": length, "fp": fp, "headers": headers}


def extensions_for(headers):
    found = list(UNIVERSAL)
    haystack = " ".join(str(v) for v in headers.values()).lower()
    for tech, exts in TECH_EXT.items():
        if tech in haystack:
            found.extend(exts)
    return sorted(set(found))


def breaks(response, sig):
    if response.status_code != sig["status"]:
        return True
    if fingerprint(response.text) != sig["fp"]:
        return True
    return abs(len(response.text) - sig["length"]) > 200


def main():
    if len(sys.argv) < 2:
        print("Usage: ./2-recursive_discovery.py <base_url> [wordlist]")
        return 1
    root = sys.argv[1].rstrip("/")
    words = WORDS
    if len(sys.argv) > 2:
        with open(sys.argv[2]) as fh:
            words = [line.strip() for line in fh if line.strip()]

    queue = deque(["/"])
    visited = set()
    while queue:
        path = queue.popleft()
        if path in visited:
            continue
        visited.add(path)
        directory = f"{root}{path}".rstrip("/")
        sig = baseline(directory)
        if sig is None:
            continue
        exts = extensions_for(sig["headers"])

        for word in words:
            r = probe(f"{directory}/{word}/")
            if r is not None and r.status_code < 500 and breaks(r, sig):
                print(f"[+] {path}{word}/   {r.status_code} len={len(r.text)}")
                if len(path.split("/")) < 5:
                    queue.append(f"{path}{word}/")
            for ext in exts:
                rf = probe(f"{directory}/{word}{ext}")
                if rf is not None and rf.status_code < 500 and breaks(rf, sig):
                    print(f"[+] {path}{word}{ext}   {rf.status_code} len={len(rf.text)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
