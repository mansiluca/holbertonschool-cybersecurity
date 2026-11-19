#!/usr/bin/python3
"""Turn environmental severity into a business action order.

Environmental severity is the closest CVSS gets to risk, but what to fix first
also depends on whether the flaw is being exploited in the wild (KEV) and how
likely exploitation is (EPSS), and on what the asset is worth to the business.
Every rank is traceable to those inputs, and the order is printed alongside the
base-score order so the places where the two disagree are explicit.
"""
import csv
import json
import os
import sys

CRITICALITY_WEIGHT = {"critical": 1.60, "high": 1.00, "medium": 0.90, "low": 0.50}
KEV_BOOST = 3.0
EPSS_WEIGHT = 1.5
CONFIRMED_BOOST = 0.5
REFUTED_PENALTY = 4.0


def load(path):
    with open(path) as handle:
        return json.load(handle)


def threat_lookup(context):
    by_cve = (context or {}).get("by_cve") or {}
    return {cve.upper(): value for cve, value in by_cve.items()}


def risk_score(entry, threat):
    env = entry.get("environmental") or 0.0
    criticality = (entry.get("criticality") or "medium").lower()
    weight = CRITICALITY_WEIGHT.get(criticality, 0.90)
    kev, epss = False, 0.0
    for cve in entry.get("cve") or []:
        info = threat.get(cve.upper())
        if info:
            kev = kev or bool(info.get("kev"))
            epss = max(epss, float(info.get("epss") or 0))
    verdict = ((entry.get("verification") or {}).get("verified") or "").lower()
    score = env * weight + (KEV_BOOST if kev else 0.0) + EPSS_WEIGHT * epss
    if verdict == "confirmed":
        score += CONFIRMED_BOOST
    elif verdict == "refuted":
        score -= REFUTED_PENALTY
    return round(score, 2), kev, epss, verdict


def priority_label(score, env, kev):
    if score <= 0:
        return "cleared"
    if env and env >= 9.0 and kev:
        return "critical"
    if score >= 15.0:
        return "critical"
    if score >= 10.0:
        return "high"
    if score >= 5.0:
        return "medium"
    return "low"


def justification(entry, kev, epss, verdict, label):
    parts = ["environmental %s on %s (%s, %s)" % (
        entry.get("environmental"), entry.get("asset"),
        entry.get("criticality") or "unknown criticality",
        entry.get("lifecycle") or "unknown lifecycle")]
    if kev:
        parts.append("KEV-listed, exploited in the wild")
    if epss:
        parts.append("EPSS %.2f" % epss)
    if verdict:
        parts.append("verification: %s" % verdict)
    parts.append("base %s is severity, this is risk" % entry.get("base"))
    return "; ".join(parts) + " -> %s" % label


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    source = args[0] if args else "outputs/rescored.json"
    context_path = args[1] if len(args) > 1 else "context/threat_context.json"
    if not os.path.exists(source):
        print("Error: no such rescored file: %s" % source, file=sys.stderr)
        return 1
    entries = load(source)
    threat = threat_lookup(load(context_path) if os.path.exists(context_path) else {})

    scored, cleared = [], []
    for entry in entries:
        if entry.get("environmental") is None:
            continue
        if (entry.get("triage") or "").lower() == "suspected_false_positive":
            # cleared: it does not belong in the action order, and the client
            # should not spend money on it
            cleared.append({"merged_id": entry.get("merged_id"), "asset": entry.get("asset"),
                            "base": entry.get("base"), "environmental": entry.get("environmental"),
                            "triage": "suspected_false_positive",
                            "signal": entry.get("signal"),
                            "cve": entry.get("cve") or []})
            continue
        score, kev, epss, verdict = risk_score(entry, threat)
        label = priority_label(score, entry.get("environmental"), kev)
        scored.append({
            "merged_id": entry.get("merged_id"),
            "asset": entry.get("asset"),
            "base": entry.get("base"),
            "environmental": entry.get("environmental"),
            "vector_version": entry.get("vector_version"),
            "kev": kev,
            "epss": round(epss, 3),
            "criticality": entry.get("criticality"),
            "confidence": entry.get("confidence"),
            "verification": verdict or "not-contested",
            "flaw": entry.get("flaw"),
            "cve": entry.get("cve") or [],
            "risk_score": score,
            "priority": label,
        })
        scored[-1]["justification"] = justification(entry, kev, epss, verdict, label)

    by_risk = sorted(scored, key=lambda e: (-e["risk_score"], e["merged_id"]))
    for rank, entry in enumerate(by_risk, 1):
        entry["rank"] = rank

    # the base-score order, for the record: where the two disagree, say so
    by_base = sorted(scored, key=lambda e: (-(e["base"] or 0), e["merged_id"]))
    base_rank = {e["merged_id"]: i for i, e in enumerate(by_base, 1)}
    inversions = []
    for entry in by_risk:
        delta = base_rank[entry["merged_id"]] - entry["rank"]
        if delta >= 3:
            inversions.append({
                "merged_id": entry["merged_id"],
                "asset": entry["asset"],
                "base_rank": base_rank[entry["merged_id"]],
                "risk_rank": entry["rank"],
                "reason": entry["justification"],
            })
    demotions = []
    for entry in by_base:
        if entry["rank"] - base_rank[entry["merged_id"]] >= 3:
            demotions.append({"merged_id": entry["merged_id"], "asset": entry["asset"],
                              "base_rank": base_rank[entry["merged_id"]],
                              "risk_rank": entry["rank"], "reason": entry["justification"]})

    payload = {"order": by_risk, "cleared": cleared, "inversions": inversions,
               "demotions": demotions, "base_order": [e["merged_id"] for e in by_base]}
    text = json.dumps(payload, indent=2)
    if "--write" in sys.argv:
        os.makedirs("outputs", exist_ok=True)
        with open(os.path.join("outputs", "priority.json"), "w") as handle:
            handle.write(text + "\n")
        with open(os.path.join("outputs", "priority.csv"), "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["rank", "merged_id", "asset", "base", "environmental", "kev",
                             "epss", "confidence", "verification", "priority", "justification"])
            for entry in by_risk:
                writer.writerow([entry["rank"], entry["merged_id"], entry["asset"],
                                 entry["base"], entry["environmental"], str(entry["kev"]).lower(),
                                 entry["epss"], entry["confidence"], entry["verification"],
                                 entry["priority"], entry["justification"]])
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
