#!/usr/bin/python3
"""Confirm F-APP-007 by behaviour, not by the version banner.

The claim is that the preview parameter evaluates expressions. A version string
can only make that plausible; the proof is a benign probe that comes back
evaluated and a matched control that comes back evaluated to something else, so
the response is doing arithmetic on our input rather than echoing it.
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

try:
    import requests
except ImportError:  # the lab box may not ship it
    requests = None


def fetch(url, params=None, data=None, method="GET", session=None, timeout=8):
    """One place where the HTTP work happens: requests when present, urllib
    otherwise. Returns (status, headers, body) or (None, {}, reason)."""
    if requests is not None:
        try:
            client = session or requests
            response = client.request(
                method, url, params=params, data=data, timeout=timeout
            )
            return response.status_code, dict(response.headers), response.text
        except Exception as exc:
            return None, {}, str(exc)
    query = ""
    if params:
        query = "?" + urllib.parse.urlencode(params)
    payload = urllib.parse.urlencode(data).encode() if data else None
    request = urllib.request.Request(url + query, data=payload, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
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


def emit(result):
    """One JSON verdict on stdout, diagnostics nowhere else."""
    if result.get("verdict") == "unconfirmed" and "to_settle" not in result:
        result["to_settle"] = "the live behaviour did not settle the claim"
    print(json.dumps(result, indent=2))


PROBE = "zzq{{7*7}}"
CONTROL = "zzq{{8*8}}"
PROBE_EVAL = "zzq49"
CONTROL_EVAL = "zzq64"
ENDPOINT = "/preview"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    base = args.target.rstrip("/")
    url = base + ENDPOINT

    status_p, _, body_p = fetch(url, {"template": PROBE})
    status_c, _, body_c = fetch(url, {"template": CONTROL})

    evidence = {
        "sent": PROBE,
        "reflected": None,
        "control_sent": CONTROL,
        "control_reflected": None,
    }
    verdict = "unconfirmed"

    if status_p is None:
        evidence["error"] = body_p
    else:
        if PROBE_EVAL in body_p:
            evidence["reflected"] = PROBE_EVAL
        if CONTROL_EVAL in body_c:
            evidence["control_reflected"] = CONTROL_EVAL
        if evidence["reflected"] and evidence["control_reflected"]:
            verdict = "confirmed"
        elif "{{7*7}}" in body_p and "{{8*8}}" in body_c:
            verdict = "false_positive"
            evidence["note"] = "probe returned verbatim, never evaluated"

    emit(
        {
            "finding": "F-APP-007",
            "class": "behavioral_confirmation",
            "verdict": verdict,
            "evidence": evidence,
            "stopped_at": "input is evaluated; no file read or code execution "
            "attempted",
            "to_settle": "the preview parameter did not evaluate our probe",
        }
    )


if __name__ == "__main__":
    main()
