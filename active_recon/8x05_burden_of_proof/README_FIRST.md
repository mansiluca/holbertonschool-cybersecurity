# 8x05 - Burden of Proof

A prior vendor handed Halcyon Cloud a scanner report with no proof behind any of
it. Your job is manual verification: take each suspected finding, prove or
disprove it with a reproducible proof of concept, and assign one of three
verdicts. You stop at presence and reachability; you never cross into impact.

## What you build (your own PoC scripts, each printing ONE JSON verdict)
  1-confirm_behavior.py     behavioural confirmation (not by version)
  2-bust_false_positive.py  disprove a confident false positive
  3-prove_injectable.py     controlled SQLi differential (no extraction)
  4-prove_xss_context.py    reflection into executable script context
  5-prove_idor.py           one unauthorized object, no enumeration
  6-prove_traversal.py      read the benign marker outside the root
  7-prove_service_path.py   socket behavioural tell (confirmed/unconfirmed)
  8-verify_tls_config.py    TLS weakness + backport false positive (JSON ARRAY)
  9-find_false_negative.py  a flaw the scanner never reported
  10-verification_report.md the client report
  README.md

## Verdict schema (every script)
  {"finding","class","verdict","evidence","stopped_at"}
  verdict in {confirmed, false_positive, unconfirmed}
  unconfirmed also requires "to_settle".
See reference/VERDICT_SCHEMA.md and reference/STOP_POINTS.md.

## Inputs
  findings/prior_findings.json   the scanner hypotheses (no verdicts)
  reference/                     VERDICT_SCHEMA.md STOP_POINTS.md TARGET_MAP.md
                                 HTTP_TEST_ACCOUNTS.md SOCKET_PROTOCOL.md
                                 verdict_schema.json
  outputs/                       put your produced JSON here if you wish

Tasks 0 and 11-14 are completed on the intranet, not here.
