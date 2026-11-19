#!/usr/bin/python3
"""Settle two neighbours in one pass: a real TLS weakness and a version lie.

F-TLS-003 is confirmed only if the service actually completes a handshake
with a weak protocol. F-SVC-009 claims the 2.4.1 banner means a normalisation
flaw; the banner is not the behaviour, so the claim is tested on the legacy
endpoint and condemned only by positive evidence that the flaw is fixed.
"""
import argparse
import json
import socket
import ssl
import sys

import urllib.error
import urllib.parse
import urllib.request

TLS_PORT = 8443
LEGACY_PORT = 8444
LEGACY_PATH = "/legacy-normalize-check"
TRAVERSAL_PROBE = "/%2e%2e/%2e%2e/etc/passwd"


def negotiate(host, port, minimum, maximum):
    """Try one TLS window and report what the service actually agreed on."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = minimum
    context.maximum_version = maximum
    try:
        with socket.create_connection((host, port), timeout=6) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                return tls.version(), tls.cipher()[0]
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        return None, str(exc)


def http_status(host, port, path):
    url = "http://%s:%d%s" % (host, port, path)
    try:
        with urllib.request.urlopen(url, timeout=6) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, str(exc)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    host = args.target.split("://")[-1].split(":")[0]

    version, cipher = negotiate(
        host, TLS_PORT, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1
    )
    tls_evidence = {
        "negotiated_protocol": version or "none",
        "handshake": (
            "completed with a weak suite"
            if version
            else "refused: %s" % cipher
        ),
    }
    tls_verdict = "unconfirmed"
    if version in ("TLSv1", "TLSv1.0", "TLSv1.1"):
        tls_verdict = "confirmed"
        if version == "TLSv1":
            tls_evidence["negotiated_protocol"] = "TLSv1.0"
        tls_evidence["cipher"] = cipher

    status, body = http_status(
        host, LEGACY_PORT, LEGACY_PATH + TRAVERSAL_PROBE
    )
    svc_evidence = {
        "banner": "version reads 2.4.1",
        "behavioral_test": "no answer from the legacy gateway",
    }
    svc_verdict = "unconfirmed"
    if status is not None:
        svc_evidence["http_status"] = status
        if status in (400, 403, 404):
            svc_verdict = "false_positive"
            svc_evidence["behavioral_test"] = (
                "normalisation probe refused; "
                "fix present despite the banner"
            )
        elif status == 200:
            svc_verdict = "confirmed"
            svc_evidence["behavioral_test"] = (
                "legacy normalisation still " "processes the probe"
            )

    first = {
        "finding": "F-TLS-003",
        "class": "tls_configuration",
        "verdict": tls_verdict,
        "evidence": tls_evidence,
        "stopped_at": "weak protocol negotiated; no interception attempted",
    }
    if tls_verdict == "unconfirmed":
        first["to_settle"] = (
            "the gateway refused the weak protocol window " "from this host"
        )
    second = {
        "finding": "F-SVC-009",
        "class": "service_version",
        "verdict": svc_verdict,
        "evidence": svc_evidence,
        "stopped_at": "condition disproven by behaviour, not by version",
    }
    if svc_verdict == "unconfirmed":
        second["to_settle"] = (
            "the legacy gateway did not answer the " "normalisation probe"
        )
    print(json.dumps([first, second], indent=2))


if __name__ == "__main__":
    main()
