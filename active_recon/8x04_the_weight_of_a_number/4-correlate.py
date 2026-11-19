#!/usr/bin/python3
"""Merge the same flaw across scanners, then classify by agreement.

Matching is on the underlying vulnerability, not on the title a scanner chose:
the same CVE on the same asset is one finding, and a flaw with no CVE is matched
on its asset plus its service plus the flaw class recognised in its text. Scanners
name one asset differently, so the asset model resolves hostname and address to
one canonical name before anything is compared.
"""
import json
import os
import re
import sys

FLAW_SIGNATURES = (
    ("log4shell", ("log4j", "jndi", "log4shell", "message lookup")),
    ("sweet32", ("sweet32", "64-bit block", "3des")),
    ("smb-signing", ("smb signing", "signing is not required", "signing disabled")),
    ("smb-null-session", ("null session", "anonymous smb")),
    ("http-sys-ms15-034", ("http.sys", "ms15-034")),
    ("poodle", ("poodle", "sslv3")),
    ("ssh-user-enum", ("username enumeration", "user enumeration")),
    ("tls-legacy-mode", ("legacy compatibility", "legacy_mode")),
    ("actuator-debug", ("actuator", "debug/actuator", "diagnostic endpoint")),
    ("diagnostics-console", ("diagnostic console", "diagnostics.php")),
    ("jquery-outdated", ("jquery",)),
    ("cert-expiry", ("certificate will expire", "certificate expiry")),
    ("cert-self-signed", ("self-signed",)),
    ("cert-cn-mismatch", ("common name", "cn mismatch")),
    ("directory-indexing", ("directory indexing", "index of /")),
    ("http-trace", ("trace method", "xst")),
    ("cookie-flags", ("httponly", "secure flag")),
    ("missing-headers", ("x-frame-options", "x-content-type-options", "x-xss-protection")),
    ("etag-inode", ("etag", "inode")),
    ("outdated-server", ("appears to be outdated", "outdated")),
    ("tcp-timestamps", ("tcp timestamps",)),
    ("icmp-timestamp", ("icmp timestamp",)),
    ("traceroute", ("traceroute", "network path")),
    ("http-redirect", ("redirects to 443", "http to https")),
    ("open-port", ("open port",)),
)
# A flaw that asserts the state of a service (protocol, cipher, certificate) can
# be contradicted by another scanner that inspected the same port and said
# nothing. A flaw that asserts the existence of a resource or a header cannot:
# silence there is not evidence.
CONTRADICTABLE = ("poodle", "sweet32", "tls-legacy-mode", "cert-expiry",
                  "cert-self-signed", "cert-cn-mismatch")


def flaw_class(*texts):
    blob = " ".join(t for t in texts if t).lower()
    for name, needles in FLAW_SIGNATURES:
        if any(n in blob for n in needles):
            return name
    words = sorted({w for w in re.findall(r"[a-z]{4,}", blob)})
    return "|".join(words[:6]) or "unknown"


def asset_index(model_path):
    """hostname <-> address, so one asset is one asset in every report."""
    index = {}
    if not (model_path and os.path.exists(model_path)):
        return index
    with open(model_path) as handle:
        model = json.load(handle)
    for entry in model.get("assets", []):
        keys = [entry.get("asset"), entry.get("ip")]
        for key in keys:
            if key:
                index[key.lower()] = entry
    return index


def canonical(finding, index):
    for key in (finding.get("asset"), finding.get("asset_ip")):
        if key and key.lower() in index:
            return index[key.lower()]["asset"]
    return finding.get("asset") or finding.get("asset_ip") or "unknown"


def parse_args(argv):
    positional, model = [], "context/asset_model.json"
    for arg in argv:
        if arg.startswith("--asset-model="):
            model = arg.split("=", 1)[1]
        elif not arg.startswith("-"):
            positional.append(arg)
    return (positional[0] if positional else "outputs/normalized.json"), model


def main():
    source, model_path = parse_args(sys.argv[1:])
    if not os.path.exists(source):
        print("Error: no such normalized file: %s" % source, file=sys.stderr)
        return 1
    with open(source) as handle:
        findings = json.load(handle)
    index = asset_index(model_path)

    scanned = {}
    for finding in findings:
        key = (canonical(finding, index), finding.get("port"))
        scanned.setdefault(key, set()).add(finding.get("source"))

    groups = {}
    for finding in findings:
        asset = canonical(finding, index)
        cves = tuple(sorted(finding.get("cve") or []))
        flaw = flaw_class(finding.get("title"), finding.get("description"))
        key = (asset, cves, flaw)
        group = groups.setdefault(key, {"asset": asset, "cve": cves, "flaw": flaw,
                                        "sources": set(), "findings": [],
                                        "ports": set(), "confidence": 0.0,
                                        "severity": "info", "locations": set(),
                                        "titles": set(), "vectors": {}})
        group["sources"].add(finding.get("source"))
        group["findings"].append(finding.get("id"))
        if finding.get("port"):
            group["ports"].add(finding["port"])
        group["confidence"] = max(group["confidence"], float(finding.get("confidence") or 0))
        rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if rank.get(finding.get("severity"), 0) > rank.get(group["severity"], 0):
            group["severity"] = finding.get("severity")
        if finding.get("location"):
            group["locations"].add(finding["location"])
        if finding.get("title"):
            group["titles"].add(finding["title"])
        cvss = finding.get("cvss")
        if cvss and cvss.get("vector"):
            group["vectors"][cvss["vector"]] = {"version": cvss.get("version"),
                                                "vector": cvss["vector"],
                                                "base_score": cvss.get("base_score")}

    merged = []
    for key in sorted(groups, key=lambda k: (k[0], k[1], k[2])):
        group = groups[key]
        sources = sorted(s for s in group["sources"] if s)
        contested = False
        if group["flaw"] in CONTRADICTABLE:
            for port in group["ports"] or {None}:
                others = scanned.get((group["asset"], port), set()) - group["sources"]
                if others:
                    contested = True
        # Agreed means more than one scanner saw it and no scanner that covered
        # the same surface contradicted it. Contested means exactly that
        # contradiction: some tools reported it, another looked and did not.
        if contested:
            classification = "contested"
        elif len(sources) > 1:
            classification = "agreed"
        else:
            classification = "unique"
        entry = {
            "merged_id": "V-%04d" % (len(merged) + 1),
            "asset": group["asset"],
            "sources": sources,
            "source_count": len(sources),
            "classification": classification,
            "contradicted": contested,
            "severity": group["severity"],
            "confidence": round(group["confidence"], 2),
            "flaw": group["flaw"],
            "service": sorted(group["ports"]),
            "findings": sorted(group["findings"]),
        }
        if group["cve"]:
            entry["cve"] = list(group["cve"])
        if group["locations"]:
            entry["location"] = sorted(group["locations"])[0]
        if group["vectors"]:
            entry["vectors"] = [group["vectors"][v] for v in sorted(group["vectors"])]
        if classification == "unique" and group["cve"] and group["confidence"] >= 0.70:
            entry["coverage_gap"] = True
        merged.append(entry)

    text = json.dumps(merged, indent=2)
    if "--write" in sys.argv:
        os.makedirs("outputs", exist_ok=True)
        with open(os.path.join("outputs", "correlated.json"), "w") as handle:
            handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
