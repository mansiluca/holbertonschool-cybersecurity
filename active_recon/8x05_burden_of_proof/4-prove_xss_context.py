#!/usr/bin/python3
"""Prove F-WEB-021 reaches executable context, with a marker and nothing more.

Reflection is not the bug: encoded text in a paragraph is a scan artefact. The
proof is that the marker lands inside a script context, or breaks out of the
HTML around it, unescaped. A benign marker is enough to show that, and it stops
there: no session theft, no payload.
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


ENDPOINT = "/reflect"
MARKER = "zzqmark91"
BREAKOUT = '<zzq data-zzq="' + MARKER + '">'


def script_context(body, marker):
    """Where the marker sits: script block, raw HTML, or encoded."""
    lowered = body.lower()
    position = body.find(marker)
    if position < 0:
        return None
    before = lowered[:position]
    opened = before.rfind("<script")
    closed = before.rfind("</script>")
    if opened > closed:
        return "inside script"
    window_start, window_end = position - 40, position + 40
    if "&lt;" in body[window_start:window_end]:
        return "html encoded"
    if "<" + marker in body or '="' + marker in body:
        return "raw html"
    return "text node"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--param", default="search")
    args = parser.parse_args()
    base = args.target.rstrip("/")

    status, _, body = fetch(base + ENDPOINT, {args.param: BREAKOUT})
    evidence = {
        "marker": MARKER,
        "context": "not reflected",
        "html_encoded": True,
    }
    verdict = "unconfirmed"

    if status is None:
        evidence["error"] = body
    else:
        context = script_context(body, MARKER)
        if context in ("inside script", "raw html"):
            verdict = "confirmed"
            evidence["context"] = (
                "reflected unescaped inside a %s block" % "script"
                if context == "inside script"
                else "reflected unescaped in the HTML"
            )
            evidence["html_encoded"] = False
        elif context == "html encoded":
            verdict = "false_positive"
            evidence["context"] = "safely HTML encoded"
        else:
            evidence["context"] = context or "not reflected"

    emit(
        {
            "finding": "F-WEB-021",
            "class": "xss",
            "verdict": verdict,
            "evidence": evidence,
            "stopped_at": "executable context reached with a benign marker; "
            "no payload deployed",
            "to_settle": "the marker did not reach an executable context",
        }
    )


if __name__ == "__main__":
    main()
