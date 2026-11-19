#!/usr/bin/python3
"""
Normalise Nikto, OpenVAS and Nessus reports into one unified schema. One
schema, three adapters. Each adapter keeps the scanner's own identifiers and
carries the source attribution correlation needs. Nothing here correlates,
triages, verifies or prioritises: it only turns three formats into one set.
"""
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

NIKTO_NOISY = (
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "httponly",
    "secure flag",
    "etag",
    "inode",
    "allowed http methods",
    "x-powered-by",
    "directory indexing",
    "appears to be outdated",
    "jquery",
    "cross-site scripting",
    "strict-transport-security",
    "server header",
    "load balancer",
)
NIKTO_STRONG = (
    # (needle, severity, confidence): real findings, whatever else is said
    ("jndi", "critical", 0.95),
    ("log4j", "critical", 0.95),
    ("diagnostic console", "high", 0.85),
    ("administrative interface", "medium", 0.80),
    ("directory indexing", "low", 0.40),
    ("trace method", "low", 0.35),
)
NIKTO_URL = re.compile(r"^(https?)://([^/:]+)(?::(\d+))?")
OV_THREAT = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "log": "info",
    "none": "info",
    "debug": "info",
}
LOCATION = re.compile(r"(/[A-Za-z0-9_\-./]*[A-Za-z0-9_\-])")


def nikto_class(description):
    """Nikto carries no severity: infer it from the check class, and mark the
    classes documented as noisy with a confidence low enough to be triaged."""
    low = description.lower()
    for needle, severity, confidence in NIKTO_STRONG:
        if needle in low:
            return severity, confidence
    if any(n in low for n in NIKTO_NOISY):
        return "info", 0.20
    return "medium", 0.60


def parse_nikto(root):
    findings, index = [], 0
    for scandetails in root.findall(".//scandetails"):
        host = scandetails.attrib.get(
            "targethostname"
        ) or scandetails.attrib.get("targetip")
        ip = scandetails.attrib.get("targetip")
        port = scandetails.attrib.get("targetport")
        scheme = (
            NIKTO_URL.match(scandetails.attrib.get("sitename", ""))
            or [None, "http"]
        )[1]
        for item in scandetails.findall(".//item"):
            index += 1
            desc = (item.findtext("description") or "").strip()
            severity, confidence = nikto_class(desc)
            uri = (item.findtext("uri") or "").strip()
            finding = {
                "id": "F-NIK-%03d" % index,
                "asset": host,
                "asset_ip": ip,
                "port": int(port) if port and port.isdigit() else None,
                "protocol": "https" if scheme == "https" else "http",
                "service": "www",
                "source": "nikto",
                "source_id": item.attrib.get("id"),
                "title": desc.split(".")[0][:120],
                "description": desc,
                "severity": severity,
                "confidence": confidence,
                "cve": sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", desc))),
                "location": uri or None,
                "cvss": None,
                "references": [],
            }
            findings.append(finding)
    return findings


def tag_value(tags, key):
    match = re.search(r"%s=([^|]+)" % re.escape(key), tags or "")
    return match.group(1).strip() if match else None


def parse_openvas(root):
    findings, index = [], 0
    for result in root.findall(".//result"):
        index += 1
        nvt = result.find("nvt")
        tags = nvt.findtext("tags") if nvt is not None else ""
        vector = tag_value(tags, "cvss_base_vector")
        qod = tag_value(tags, "qod")
        try:
            confidence = float(qod) / 100.0 if qod else 0.70
        except ValueError:
            confidence = 0.70
        port_text = (result.findtext("port") or "").strip()
        port, _, proto = port_text.partition("/")
        cves = []
        if nvt is not None:
            cves = sorted(
                {
                    ref.attrib.get("id", "")
                    for ref in nvt.findall("./refs/ref")
                    if ref.attrib.get("type") == "cve" and ref.attrib.get("id")
                }
            )
        base = nvt.findtext("cvss_base") if nvt is not None else None
        if base is None:
            base = (result.findtext("severity") or "0").strip()
        desc = (result.findtext("description") or "").strip()
        location = LOCATION.search(desc)
        findings.append(
            {
                "id": "F-OV-%03d" % index,
                "asset": (result.findtext("host") or "").strip(),
                "asset_ip": (result.findtext("host") or "").strip(),
                "port": int(port) if port.isdigit() else None,
                "protocol": proto or None,
                "service": (result.findtext("name") or "").strip()[:60],
                "source": "openvas",
                "source_id": (
                    nvt.attrib.get("oid") if nvt is not None else None
                ),
                "title": (result.findtext("name") or "").strip(),
                "description": desc,
                "severity": OV_THREAT.get(
                    (result.findtext("threat") or "log").strip().lower(),
                    "info",
                ),
                "confidence": round(confidence, 2),
                "cve": cves,
                "location": location.group(1) if location else None,
                "cvss": (
                    {
                        "version": "3.1",
                        "vector": vector,
                        "base_score": float(base),
                    }
                    if vector
                    else None
                ),
                "references": [],
            }
        )
    return findings


NESSUS_SEVERITY = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}


def parse_nessus(root):
    findings = []
    for report_host in root.findall(".//ReportHost"):
        props = {
            tag.attrib.get("name"): (tag.text or "").strip()
            for tag in report_host.findall("./HostProperties/tag")
        }
        for item in report_host.findall("./ReportItem"):
            plugin = item.attrib.get("pluginID", "")
            vector = (
                item.findtext("cvss3_vector")
                or item.findtext("cvss4_vector")
                or ""
            ).strip()
            base = (
                item.findtext("cvss3_base_score")
                or item.findtext("cvss_base_score")
                or "0"
            )
            output = (item.findtext("plugin_output") or "").strip()
            location = LOCATION.search(output)
            cves = sorted(
                {
                    (c.text or "").strip()
                    for c in item.findall("cve")
                    if (c.text or "").strip()
                }
            )
            findings.append(
                {
                    "id": "F-NES-%s" % plugin,
                    "asset": props.get("host-fqdn")
                    or report_host.attrib.get("name"),
                    "asset_ip": props.get("host-ip")
                    or report_host.attrib.get("name"),
                    "port": int(item.attrib.get("port") or 0),
                    "protocol": item.attrib.get("protocol"),
                    "service": item.attrib.get("svc_name"),
                    "source": "nessus",
                    "source_id": plugin,
                    "title": item.attrib.get("pluginName"),
                    "description": (
                        item.findtext("description") or ""
                    ).strip(),
                    "severity": NESSUS_SEVERITY.get(
                        item.attrib.get("severity", "0"), "info"
                    ),
                    "confidence": (
                        0.90
                        if item.attrib.get("severity", "0") != "0"
                        else 0.50
                    ),
                    "cve": cves,
                    "location": location.group(1) if location else None,
                    "cvss": (
                        {
                            "version": (
                                "4.0"
                                if vector.startswith("CVSS:4.0")
                                else "3.1"
                            ),
                            "vector": vector,
                            "base_score": float(base),
                        }
                        if vector
                        else None
                    ),
                    "references": [],
                }
            )
    return findings


def parse(path):
    if path.lower().endswith(".json"):
        with open(path) as handle:
            return json.load(handle)
    root = ET.parse(path).getroot()
    if root.tag == "niktoscan":
        return parse_nikto(root)
    if root.tag == "NessusClientData_v2":
        return parse_nessus(root)
    if root.find(".//nvt") is not None:
        return parse_openvas(root)
    raise SystemExit("unknown report format: %s" % path)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not args:
        print(
            "Usage: ./1-normalizer.py <report> [<report> ...]", file=sys.stderr
        )
        return 1
    findings = []
    for path in args:
        if not os.path.exists(path):
            print("Error: no such report: %s" % path, file=sys.stderr)
            return 1
        findings.extend(parse(path))
    out = (
        os.path.join("outputs", "normalized.json")
        if "--write" in sys.argv
        else None
    )
    text = json.dumps(findings, indent=2)
    if out:
        os.makedirs("outputs", exist_ok=True)
        with open(out, "w") as handle:
            handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
