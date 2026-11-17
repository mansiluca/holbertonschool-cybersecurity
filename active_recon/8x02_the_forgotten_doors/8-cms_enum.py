#!/usr/bin/python3
"""Drive the CMS enumeration tooling, then do the work it does not: parse the
surface, enumerate users, pin the exact plugin version, map it to the local
vulnerability database."""
import json
import os
import re
import shutil
import subprocess
import sys

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

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ridgeline-enum/1.0)"}
PLUGIN_PATTERN = re.compile(r'/wp-content/plugins/([a-z0-9\-_]+)/', re.I)
SCRIPT_VER = re.compile(r'/wp-content/plugins/([a-z0-9\-_]+)/[^"\']*?\?ver=([0-9][0-9.]*)', re.I)
STABLE_TAG = re.compile(r'Stable tag:\s*([0-9][0-9.]*)', re.I)


def orchestrate(url):
    """Reuse the public tooling for what it is good at; the analysis is ours."""
    if not shutil.which("wpscan"):
        return None
    try:
        out = subprocess.run(["wpscan", "--url", url, "--no-banner", "--format", "json",
                              "--disable-tls-checks"], capture_output=True, text=True, timeout=180)
        return json.loads(out.stdout) if out.stdout.strip().startswith("{") else None
    except (subprocess.SubprocessError, ValueError):
        return None


def enumerate_users(url, scan):
    users = set()
    r = http(f"{url}/wp-json/wp/v2/users", headers=HEADERS)
    if r is not None and r.status_code == 200 and "json" in r.headers.get("Content-Type", ""):
        try:
            for entry in json.loads(r.text):
                slug = entry.get("slug") or entry.get("name")
                if slug:
                    users.add(slug.replace(" ", ".").lower())
        except (ValueError, AttributeError):
            pass
    if scan:
        for entry in (scan.get("users") or {}):
            users.add(str(entry).lower())
    return sorted(users)


def enumerate_plugins(url, scan):
    plugins = {}
    for page in ("", "/blog", "/?p=1"):
        r = http(url + page, headers=HEADERS)
        if r is None:
            continue
        for name, version in SCRIPT_VER.findall(r.text):
            plugins.setdefault(name.lower(), version)
        for name in PLUGIN_PATTERN.findall(r.text):
            plugins.setdefault(name.lower(), None)
    if scan:
        for name, data in (scan.get("plugins") or {}).items():
            plugins.setdefault(name.lower(), (data.get("version") or {}).get("number"))
    for name, version in list(plugins.items()):
        if version:
            continue
        r = http(f"{url}/wp-content/plugins/{name}/readme.txt", headers=HEADERS)
        if r is not None and r.status_code == 200:
            hit = STABLE_TAG.search(r.text)
            if hit:
                plugins[name] = hit.group(1)
    return sorted(plugins.items())


def analyze(plugin, version, db_path):
    """The lookup the binary does not do for us: exact version against the local DB."""
    if not (version and os.path.exists(db_path)):
        return None
    try:
        with open(db_path) as fh:
            db = json.load(fh)
    except (OSError, ValueError):
        return None
    entries = db if isinstance(db, list) else (db.get("plugins") or db.get("vulnerabilities") or [])
    for entry in entries:
        if not isinstance(entry, dict) or plugin not in json.dumps(entry).lower():
            continue
        fixed = str(entry.get("fixed_in") or entry.get("patched_version") or "")
        if fixed and version >= fixed:
            return f"{entry.get('cve', 'advisory')} fixed in {fixed}, {plugin} {version} is patched"
        return f"{entry.get('cve', 'advisory')} affects {plugin} {version} ({entry.get('title', 'known issue')})"
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: ./8-cms_enum.py <url> [db_path]")
        return 1
    url = sys.argv[1].rstrip("/")
    db_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "reference", "vulnerability_db.json")
    scan = orchestrate(url)

    for user in enumerate_users(url, scan):
        print(f"[+] user    {user}")
    for plugin, version in enumerate_plugins(url, scan):
        print(f"[+] plugin  {plugin} {version or '(version unknown)'}")
        finding = analyze(plugin, version, db_path)
        if finding:
            print(f"    -> {finding}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
