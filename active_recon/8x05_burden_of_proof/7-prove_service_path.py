#!/usr/bin/python3
"""Prove F-SVC-022 at the socket layer, and stop at presence.

A banner is a rumour, in this protocol too. The tell is behavioural: the
service answers an open command set without authentication. If the limits
of the engagement leave it ambiguous, the verdict is `unconfirmed` with what
would settle it, not a guess.
"""
import argparse
import json
import socket
import sys

BANNER_LIMIT = 512


def exchange(host, port, command, timeout=6):
    """Connect, read the banner, send one line, read the answer."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        banner = sock.recv(BANNER_LIMIT).decode("utf-8", "replace").strip()
        sock.sendall(command.encode() + b"\r\n")
        answer = sock.recv(BANNER_LIMIT).decode("utf-8", "replace").strip()
        return banner, answer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=16379)
    args = parser.parse_args()

    evidence = {"probe": "PING", "response": None, "auth_required": None}
    verdict = "unconfirmed"
    settle = "the service did not answer the open command set"

    try:
        banner, answer = exchange(args.target, args.port, "PING")
        evidence["banner"] = banner
        evidence["response"] = answer
        if answer.startswith("+PONG"):
            verdict = "confirmed"
            evidence["auth_required"] = False
        elif "AUTH" in answer.upper():
            verdict = "false_positive"
            evidence["auth_required"] = True
            settle = "the open command set requires authentication"
        else:
            settle = "the answer to PING was neither PONG nor an auth gate"
    except (OSError, socket.timeout) as exc:
        evidence["error"] = str(exc)
        settle = "the diagnostic service is not reachable from here"

    result = {
        "finding": "F-SVC-022",
        "class": "service_vulnerability",
        "verdict": verdict,
        "evidence": evidence,
        "stopped_at": "unauthenticated code path reachable; no data read, "
        "no exploit run",
    }
    if verdict == "unconfirmed":
        result["to_settle"] = settle
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
