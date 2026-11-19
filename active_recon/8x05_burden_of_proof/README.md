# 8x05 - Burden of Proof

Manual verification of a prior vendor's scanner findings against a live slice of
the Halcyon Cloud estate. Every finding is a hypothesis; each script runs the
experiment and prints one JSON verdict.

## Scripts

| script | finding | proof | stops at |
|---|---|---|---|
| `1-confirm_behavior.py` | F-APP-007 | probe `zzq{{7*7}}` evaluates to `zzq49`, control to `zzq64` | input evaluated |
| `2-bust_false_positive.py` | F-WEB-002 | error identical for malicious, benign and empty input | condition disproven |
| `3-prove_injectable.py` | F-WEB-014 | boolean pair + time differential on `id` | injectability, no extraction |
| `4-prove_xss_context.py` | F-WEB-021 | benign marker unescaped in script context | context reachable |
| `5-prove_idor.py` | F-WEB-033 | member A reads invoice 1041 owned by B | one object |
| `6-prove_traversal.py` | F-WEB-040 | `proof_marker.txt` content outside the root | benign marker |
| `7-prove_service_path.py` | F-SVC-022 | `PING` -> `+PONG` without authentication | open command set |
| `8-verify_tls_config.py` | F-TLS-003 + F-SVC-009 | handshake negotiation, behaviour vs banner | condition established |
| `9-find_false_negative.py` | DISCOVERED-001 | member performs an approval | flaw present |
| `10-verification_report.md` | - | the client report | - |

## Usage

    ./1-confirm_behavior.py --target https://app.halcyon.example
    ./3-prove_injectable.py --target https://app.halcyon.example --param id
    ./7-prove_service_path.py --target halcyon.example --port 16379
    ./8-verify_tls_config.py --target halcyon.example:8443

Every script emits `{finding, class, verdict, evidence, stopped_at}`; task 8 emits
an array of two. `verdict` is one of `confirmed`, `false_positive`, `unconfirmed`,
and an unconfirmed verdict always carries `to_settle`.

## Inputs

`findings/prior_findings.json` (scanner hypotheses, no verdicts), `reference/`
(verdict schema, stop points, target map, test accounts, socket protocol),
`rules_of_engagement.md`. Outputs may be written to `outputs/`.

## Discipline

Presence and reachability only. No extraction, no enumeration beyond one object, no
weaponised payload, no exploit run, no interception. Could-not-reproduce stays
`unconfirmed`.
