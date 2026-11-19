#!/usr/bin/python3
"""
Confirm or refute contested findings against the live estate. The scanner is
not the system. For each finding triage could not settle, this probes the
target the finding names and decides on what the service actually returns. Safe
methods only: GET, plus OPTIONS where the finding is about methods. Nothing is
exploited, nothing is modified.
"""
import json
import os
import socket
import sys
import urllib.error
import urllib.request

PORT = 8080
UA = {"User-Agent": "ridgeline-verify/1.0"}

# what a confirming response looks like, per flaw class
CONFIRM_MARKERS = {
    "tls-legacy-mode": ("accepted=true", "legacy_mode"),
    "actuator-debug": ("environment", "framework"),
    "diagnostics-console": ("build", "environment"),
    "smb-null-session": ("anonymous", "null"),
    "ssh-user-enum": ("timing", "enumeration"),
    "http-trace": ("trace",),
    "directory-indexing": ("index of",),
}


def port_open(target, port=PORT, timeout=4):
    """Talk to the service before trusting the HTTP client: a closed port and a
    refused request are different evidence, and only one of them is about the
    finding."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(256).decode("utf-8", "replace").strip()
            except (socket.timeout, OSError):
                banner = ""
            return True, banner
    except (OSError, socket.timeout) as exc:
        return False, str(exc)


def request(url, method="GET"):
    req = urllib.request.Request(url, method=method, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=6) as response:
            return (
                response.status,
                dict(response.headers),
                response.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            dict(exc.headers or {}),
            exc.read().decode("utf-8", "replace"),
        )
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return None, {}, str(exc)


def verdict(finding, target):
    """Returns the verification block for one finding."""
    location = finding.get("location")
    flaw = finding.get("flaw") or ""
    if not location:
        return {
            "verified": "not-probeable",
            "evidence": "no resource path in the scanner output to probe",
            "target": target,
        }
    reachable, banner = port_open(target)
    if not reachable:
        return {"verified": "unreachable",
                "evidence": "tcp %s:%d refused or timed out (%s)"
                            % (target, PORT, banner),
                "target": target}
    url = "http://%s:%d%s" % (target, PORT, location)
    status, headers, body = request(url)
    if status is None:
        return {
            "verified": "unreachable",
            "evidence": "no response from %s: %s" % (url, body),
            "target": target,
        }
    if status == 404:
        return {
            "verified": "refuted",
            "evidence": "claimed resource %s returns 404 on the live host"
            % location,
            "target": target,
        }
    if status >= 500:
        return {
            "verified": "refuted",
            "evidence": "%s answers %d on the live host" % (location, status),
            "target": target,
        }
    markers = CONFIRM_MARKERS.get(flaw, ())
    lowered = body.lower()
    hits = [m for m in markers if m in lowered]
    if hits:
        return {
            "verified": "confirmed",
            "evidence": "live response from %s exposes %s"
            % (location, ", ".join(hits)),
            "target": target,
        }
    if status == 200:
        return {
            "verified": "refuted",
            "evidence": "%s answers 200 but the claimed condition is absent"
            % location,
            "target": target,
        }
    return {
        "verified": "refuted",
        "evidence": "%s answers %d, not the claimed state"
        % (location, status),
        "target": target,
    }


def parse_args(argv):
    """`--target host` and `--target=host` are the same request."""
    positional, target = [], None
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg.startswith("--target="):
            target = arg.split("=", 1)[1]
        elif arg == "--target" and index + 1 < len(argv):
            index += 1
            target = argv[index]
        elif not arg.startswith("-"):
            positional.append(arg)
        index += 1
    return (positional[0] if positional else None), target


def main():
    source, target = parse_args(sys.argv[1:])
    if source is None:
        source = "needs_verification.json"
    if not os.path.exists(source) and os.path.exists(
            os.path.join("outputs", "needs_verification.json")):
        source = os.path.join("outputs", "needs_verification.json")
    if not target:
        print(
            "Usage: ./7-verify.py needs_verification.json "
            "--target <host>",
            file=sys.stderr,
        )
        return 1
    if not os.path.exists(source):
        print("Error: no such triaged file: %s" % source, file=sys.stderr)
        return 1
    with open(source) as handle:
        pending = json.load(handle)

    # the pending set is what gets probed; the rest of the correlated estate is
    # carried through so the re-scoring stage still sees every finding
    findings = pending
    full = os.path.join(os.path.dirname(source) or ".", "triaged.json")
    if (os.path.exists(full)
            and os.path.abspath(full) != os.path.abspath(source)):
        with open(full) as handle:
            findings = json.load(handle)
        probed = {f.get("merged_id") for f in pending}
        findings = [f for f in findings
                    if f.get("merged_id") in probed
                    or f.get("triage") != "needs_verification"]
        seen = {f.get("merged_id") for f in findings}
        findings.extend(f for f in pending if f.get("merged_id") not in seen)

    out = []
    for finding in findings:
        if finding.get("triage") != "needs_verification":
            block = {"verified": "not-contested",
                     "evidence": "triage did not require verification",
                     "target": target}
        else:
            block = verdict(finding, finding.get("asset") or target)
        # one explicit record per finding: the id, the verdict, the evidence
        out.append({
            "merged_id": finding.get("merged_id"),
            "asset": finding.get("asset"),
            "target": block["target"],
            "verified": block["verified"],
            "evidence": block["evidence"],
            "triage": finding.get("triage"),
            "signal": finding.get("signal"),
            "cve": finding.get("cve") or [],
            "flaw": finding.get("flaw"),
            "severity": finding.get("severity"),
            "vectors": finding.get("vectors") or [],
        })

    text = json.dumps(out, indent=2)
    if "--write" in sys.argv:
        os.makedirs("outputs", exist_ok=True)
        with open(os.path.join("outputs", "verified.json"), "w") as handle:
            handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
