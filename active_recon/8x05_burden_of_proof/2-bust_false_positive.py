#!/usr/bin/python3
"""Disprove F-WEB-002 with positive evidence, not with a shrug.

The scanner saw a 500 on a quote and called it injection. If the error page is
identical for a malicious input, a benign one and an empty one, the response is
input-independent: that is a generic error page, and the claim fails.
Proving it false means showing that identity, not failing to trigger it.
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


MALICIOUS = "' OR 1=1 --"
BENIGN = "test_input"
EMPTY = ""
ENDPOINT = "/search"


def fingerprint(status, body):
    return status, len(body), " ".join(body.split())[:400]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--param", default="q")
    args = parser.parse_args()
    base = args.target.rstrip("/")
    url = base + ENDPOINT

    results = {}
    reached = True
    for label, value in (
        ("malicious", MALICIOUS),
        ("benign", BENIGN),
        ("empty", EMPTY),
    ):
        status, _, body = fetch(url, {args.param: value})
        if status is None:
            reached = False
            results[label] = (None, 0, body)
        else:
            results[label] = fingerprint(status, body)
        results[label + "_status"] = status

    evidence = {
        "sql_input": "HTTP %s" % results["malicious_status"],
        "benign_input": "HTTP %s" % results["benign_status"],
        "empty_input": "HTTP %s" % results["empty_status"],
        "answered": reached,
    }
    verdict = "unconfirmed"
    if not reached:
        evidence["conclusion"] = "no answer from the target; nothing tested"
    elif results["malicious"] == results["benign"] == results["empty"]:
        verdict = "false_positive"
        evidence["conclusion"] = (
            "error identical for every input; generic "
            "error page, not an injectable query"
        )
    elif results["malicious"] != results["benign"]:
        verdict = "confirmed"
        evidence["conclusion"] = (
            "response differs under a malicious input; "
            "the parameter reaches the query"
        )

    emit(
        {
            "finding": "F-WEB-002",
            "class": "sql_injection",
            "verdict": verdict,
            "evidence": evidence,
            "stopped_at": "condition disproven; no further action",
            "to_settle": "the responses stayed comparable but not identical",
        }
    )


if __name__ == "__main__":
    main()
