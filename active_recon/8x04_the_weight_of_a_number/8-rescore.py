#!/usr/bin/python3
"""Move each finding from base severity to environmental severity for this estate.

The base score is the same on every planet. This is the part that knows one host
is the payment database and another is a decommissioned box behind a firewall:
the asset model's security requirements become CR/IR/AR, its network position and
lifecycle become the modified attack vector. Base is preserved next to the
environmental score so the shift stays legible. No exploitation state is written.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference"))
from cvss_helper import detect_version, environmental_score, with_environment  # noqa: E402

REQ = {"H": "H", "M": "M", "L": "L"}
# where the host sits decides how far away an attacker must be
MAV = {"internet-facing": "N", "internal-reachable": "A", "isolated": "L"}
# the same flaw does not weigh the same on a crown jewel and on a dead host.
# modified impact metrics take N/L/H only, so a medium requirement becomes L:
# the vocabulary has no middle for how much a loss weighs here.
IMPACT_BY_CRITICALITY = {"critical": "requirement", "high": "requirement",
                         "medium": "requirement", "low": "L"}
IMPACT_VALUE = {"H": "H", "M": "L", "L": "L"}


def load_assets(path):
    with open(path) as handle:
        model = json.load(handle)
    index = {}
    for entry in model.get("assets", []):
        for key in (entry.get("asset"), entry.get("ip")):
            if key:
                index[key.lower()] = entry
    return index


def environmental_mods(asset, version):
    """Asset criticality and position -> CVSS environmental metrics.

    Security requirements become CR/IR/AR. Position and lifecycle become the
    modified attack vector, and an isolated host also gets a harder attack
    complexity: reaching it at all is the expensive part. Impact modifiers carry
    the analyst's re-assessment: on a crown jewel the loss weighs at least what
    the business requires, on a decommissioned box it weighs little.
    """
    if not asset:
        return {}
    reqs = asset.get("security_requirements") or {}
    c = REQ.get((reqs.get("C") or "").upper(), "M")
    i = REQ.get((reqs.get("I") or "").upper(), "M")
    a = REQ.get((reqs.get("A") or "").upper(), "M")
    mods = {"CR": c, "IR": i, "AR": a}
    position = asset.get("network_position") or ""
    isolated = asset.get("lifecycle") == "decommissioned" or position == "isolated"
    if isolated:
        position = "isolated"
    if position in MAV:
        mods["MAV"] = MAV[position]
    if isolated:
        mods["MAC"] = "H"
    criticality = asset.get("criticality") or "medium"
    if IMPACT_BY_CRITICALITY.get(criticality) == "L":
        c = i = a = "L"
    if version == "4.0":
        mods.update({"MVC": IMPACT_VALUE[c], "MVI": IMPACT_VALUE[i], "MVA": IMPACT_VALUE[a]})
    else:
        mods.update({"MC": IMPACT_VALUE[c], "MI": IMPACT_VALUE[i], "MA": IMPACT_VALUE[a]})
    return mods


def rescore(finding, assets):
    vectors = finding.get("vectors") or []
    cvss = None
    if vectors:
        # v4.0 first: it is the current vocabulary, v3.1 kept alongside when both exist
        ordered = sorted(vectors, key=lambda v: (v.get("version") != "4.0", v.get("vector")))
        cvss = ordered[0]
    asset = assets.get(str(finding.get("asset", "")).lower(), {})
    version = detect_version(cvss["vector"]) if cvss else None
    mods = environmental_mods(asset, version)
    entry = {"merged_id": finding.get("merged_id"), "asset": finding.get("asset"),
             "criticality": asset.get("criticality"),
             "network_position": asset.get("network_position"),
             "lifecycle": asset.get("lifecycle")}
    if not cvss:
        entry.update({"vector_version": None, "base": None, "environmental": None,
                      "note": "no CVSS vector in the scanner output, severity carried as-is"})
        return entry
    vector = cvss["vector"]
    base = float(cvss.get("base_score") or 0)
    modified = with_environment(vector, mods)
    env = environmental_score(modified)
    entry.update({
        "vector_version": version,
        "vector": vector,
        "base": round(base, 1),
        "environmental": round(env, 1),
        "delta": round(env - base, 1),
        "environmental_vector": modified,
        "environmental_metrics": mods,
    })
    others = [v["version"] for v in vectors if v["vector"] != vector]
    if others:
        entry["also_reported_as"] = sorted(set(others))
    return entry


def cvss_of_merged(finding):
    return finding.get("cvss")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    source = args[0] if args else "outputs/verified.json"
    model = args[1] if len(args) > 1 else "context/asset_model.json"
    if not os.path.exists(source):
        print("Error: no such verified file: %s" % source, file=sys.stderr)
        return 1
    with open(source) as handle:
        findings = json.load(handle)
    assets = load_assets(model)

    out = []
    for finding in findings:
        entry = rescore(finding, assets)
        for key in ("cve", "flaw", "triage", "signal", "verification", "confidence", "sources"):
            if finding.get(key):
                entry[key] = finding[key]
        out.append(entry)

    text = json.dumps(out, indent=2)
    if "--write" in sys.argv:
        os.makedirs("outputs", exist_ok=True)
        with open(os.path.join("outputs", "rescored.json"), "w") as handle:
            handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
