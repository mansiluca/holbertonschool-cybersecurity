#!/usr/bin/python3
"""Neutral CVSS helper for 8x04.

Generic vector parsing and scoring for CVSS v3.1 and v4.0, backed by the vetted
`cvss` library. It knows nothing about Aurum Pay: no asset mapping, no final
scores, no ranking. Your 8-rescore.py decides how the asset model becomes
environmental metrics; this helper only turns a vector string into a number.

Public functions
----------------
detect_version(vector)            -> "3.1" | "4.0"
base_score(vector)                -> float (the environment-independent base)
environmental_score(vector)       -> float (vector incl. env metrics)
with_environment(base_vector, mods) -> str  (append/override env)

`mods` is a plain dict of CVSS metric abbreviations to values, e.g.
{"CR": "H", "IR": "H", "AR": "H", "MAV": "N"} for v3.1/v4.0. No interpretation
of what those values *should* be for a given asset happens here.
"""
from cvss import CVSS3, CVSS4


def detect_version(vector):
    """Return '4.0' or '3.1' from the vector prefix; raise otherwise."""
    v = (vector or "").strip()
    if v.startswith("CVSS:4.0/"):
        return "4.0"
    if v.startswith("CVSS:3.1/") or v.startswith("CVSS:3.0/"):
        return "3.1"
    raise ValueError("unrecognised CVSS vector: %r" % vector)


def _obj(vector):
    return CVSS4(vector) if detect_version(vector) == "4.0" else CVSS3(vector)


def base_score(vector):
    """Base score, ignoring any environmental metrics present in the vector."""
    if detect_version(vector) == "4.0":
        # v4.0 base = score of the vector with environmental metrics stripped.
        base_only = _strip_env(vector)
        return float(CVSS4(base_only).base_score)
    return float(CVSS3(vector).scores()[0])


def environmental_score(vector):
    """Environmental score of a vector that already carries env metrics."""
    o = _obj(vector)
    if detect_version(vector) == "4.0":
        return float(o.base_score)
    return float(o.scores()[2])


_ENV_PREFIXES = (
    "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI",
    "MS", "MC", "MI", "MA", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
)


def _is_env_metric(token):
    key = token.split(":", 1)[0]
    return key in _ENV_PREFIXES


def _strip_env(vector):
    head, rest = vector.split("/", 1)
    kept = [t for t in rest.split("/") if not _is_env_metric(t)]
    return head + "/" + "/".join(kept)


def with_environment(base_vector, mods):
    """Return a new vector string with the given environmental metrics applied.

    Existing copies of those metrics are replaced; the rest of the vector is
    preserved. Pure string work: no judgement about which values are correct.
    """
    head, rest = base_vector.split("/", 1)
    tokens = [t for t in rest.split("/") if t]
    out = []
    override = {k: str(v) for k, v in mods.items()}
    seen = set()
    for t in tokens:
        key = t.split(":", 1)[0]
        if key in override:
            out.append("%s:%s" % (key, override[key]))
            seen.add(key)
        else:
            out.append(t)
    for key, val in override.items():
        if key not in seen:
            out.append("%s:%s" % (key, val))
    return head + "/" + "/".join(out)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vec = sys.argv[1]
        print("version=%s base=%s env=%s" % (
            detect_version(vec), base_score(vec), environmental_score(vec)))
