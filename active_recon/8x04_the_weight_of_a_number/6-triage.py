#!/usr/bin/python3
"""
Separate correlated findings into trusted, suspected false positive and needs-
verification, using signals that can be defended to a client. A single-source
finding is not automatically false and agreement is not proof: the signals are
cross-scanner contradiction, confidence too low to act on, the asset model's
own record of the host, and single-source coverage of a crown jewel.
"""
import json
import os
import sys

CROWN_JEWEL_CRITICALITY = ("critical",)


def load_assets(path):
    if not (path and os.path.exists(path)):
        return {}
    with open(path) as handle:
        model = json.load(handle)
    index = {}
    for entry in model.get("assets", []):
        for key in (entry.get("asset"), entry.get("ip")):
            if key:
                index[key.lower()] = entry
    return index


def triage(finding, assets):
    sources = finding.get("sources") or []
    confidence = float(finding.get("confidence") or 0)
    asset = assets.get(str(finding.get("asset", "")).lower(), {})
    criticality = asset.get("criticality")
    lifecycle = asset.get("lifecycle")

    if finding.get("contradicted"):
        return "suspected_false_positive", "cross-scanner-contradiction"
    if confidence and confidence < 0.50:
        return "suspected_false_positive", "low-confidence"
    if finding.get("classification") == "agreed":
        return "trusted", "cross-scanner-agreement"
    if finding.get("classification") == "contested":
        return "needs_verification", "partial-agreement"
    if len(sources) == 1:
        if criticality in CROWN_JEWEL_CRITICALITY:
            return "needs_verification", "single-source-on-crown-jewel"
        if lifecycle == "decommissioned":
            return "needs_verification", "single-source-on-decommissioned-host"
        return "needs_verification", "single-source-coverage-gap"
    return "needs_verification", "unclassified-signal"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    source = args[0] if args else "outputs/correlated.json"
    model = "context/asset_model.json"
    for arg in sys.argv[1:]:
        if arg.startswith("--asset-model="):
            model = arg.split("=", 1)[1]
    if not os.path.exists(source):
        print("Error: no such correlated file: %s" % source, file=sys.stderr)
        return 1
    with open(source) as handle:
        findings = json.load(handle)
    assets = load_assets(model)

    out = []
    for finding in findings:
        verdict, signal = triage(finding, assets)
        entry = {
            "merged_id": finding.get("merged_id"),
            "triage": verdict,
            "signal": signal,
            "asset": finding.get("asset"),
            "sources": finding.get("sources"),
            "classification": finding.get("classification"),
            "confidence": finding.get("confidence"),
            "severity": finding.get("severity"),
        }
        for key in ("cve", "location", "flaw", "vectors"):
            if finding.get(key):
                entry[key] = finding[key]
        out.append(entry)

    text = json.dumps(out, indent=2)
    if "--write" in sys.argv:
        os.makedirs("outputs", exist_ok=True)
        with open(os.path.join("outputs", "triaged.json"), "w") as handle:
            handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
