# Verification Report, Halcyon Cloud
For: Halcyon Cloud and the Ridgeline engagement lead

## 1. Executive summary

The prior vendor delivered two hundred findings and no proof. This engagement took
the subset that mattered and put each one on trial. Of the findings handed over,
four are real and proven, one is a confident false positive that would have cost a
sprint, one sits behind an access limit and is reported as unconfirmed rather than
guessed, and one genuine flaw the scanner never reported was found by hand.

What that means for remediation: fix the template evaluation, the injectable
lookup parameter, the reflection context, the invoice authorization gap and the
unauthenticated diagnostic path. Do not spend anything on the search-parameter
injection the scanner flagged in red; it is a generic error page, proven so. Treat
the authenticated diagnostic export as open until an account is supplied, and add
the missing role check on the approval action to the backlog with the same
priority as the confirmed findings, because nobody scanned for it.

## 2. Per-finding verdicts

| finding | asset | class | verdict | proof | stopped at |
|---|---|---|---|---|---|
| F-APP-007 | app.halcyon.example | behavioral_confirmation | confirmed | `zzq{{7*7}}` returns `zzq49`, control `zzq{{8*8}}` returns `zzq64` | input is evaluated |
| F-WEB-002 | app.halcyon.example | sql_injection | false_positive | 500 identical for malicious, benign and empty input | generic error page |
| F-WEB-014 | app.halcyon.example | sql_injection | confirmed | boolean pair and time differential on `id` | injectability |
| F-WEB-021 | app.halcyon.example | xss | confirmed | benign marker lands unescaped in script context | context reachable |
| F-WEB-033 | app.halcyon.example | broken_access_control | confirmed | member A receives invoice 1041 owned by B | one object |
| F-WEB-040 | app.halcyon.example | path_traversal | confirmed | `proof_marker.txt` content returned outside the root | benign marker |
| F-SVC-022 | halcyon.example:16379 | service_vulnerability | confirmed | `PING` answers `+PONG` without authentication | open command set |
| F-TLS-003 | halcyon.example:8443 | tls_configuration | confirmed | weak protocol negotiated by handshake | protocol negotiated |
| F-SVC-009 | halcyon.example:8444 | service_version | false_positive | normalisation probe refused; fix present despite 2.4.1 | condition disproven by behaviour |
| F-SVC-031 | halcyon.example:16379 | service_vulnerability | unconfirmed | `ADMINSTATS` gated; no account supplied | access limit |

Each verdict is produced by its script and printed as one JSON object with
`finding`, `class`, `verdict`, `evidence` and `stopped_at`, so any line above can
be reproduced by re-running the script named in section 7.

## 3. False positives cleared

F-WEB-002, the search parameter, arrived with the scanner's highest confidence and
the least evidence: a 500 on a single quote. Sent three inputs, the malicious
`' OR 1=1 --`, a benign string, and nothing, the service answers the same error,
byte for byte, every time. A response that does not move with the input is not a
query you can influence; it is a generic failure page. That is positive evidence of
absence, not a failure to trigger.

F-SVC-009, the legacy gateway, arrived on a version banner: 2.4.1 is associated
with a known normalisation flaw. Tested behaviourally, the normalisation probe is
refused, which means the fix is present despite the banner. The version lied; the
service told the truth.

## 4. Unconfirmed findings

F-SVC-031 claims the authenticated diagnostic command set exports configuration.
The service answers the open commands, and `ADMINSTATS` does not answer without
credentials. Proving that claim would need a diagnostic account, which the
engagement did not supply. Could not reproduce is not the same as does not exist,
so it stays unconfirmed with what would settle it rather than sliding into the false
positive column.

## 5. The missed vulnerability

The prior assessment never reported a missing role check on the approval action, a
class automated tools are structurally blind to: the tool does not know who is
allowed to do what. A member account lists the team actions and performs the
approval, in two requests, and the application accepts it. That is the flaw, proven
with a minimal reproducible sequence, with impact deliberately left undemonstrated.

## 6. The verification line

Every confirmed finding stopped at presence and reachability. The injection was
proven by a differential, and stopped before any extraction: no UNION, no dump, no
file read. The reflection was proven with a benign marker, and stopped before any
weaponised payload, so no session was at risk. The authorization gap was proven on
one invoice, and stopped before any enumeration, so no second principal's data was
touched. The traversal read the one file the estate keeps outside the root as a
proof marker, and stopped before anything that matters. The diagnostic service was
spoken to and stopped before any privileged command. The TLS weakness was
negotiated and stopped before any interception.

Impact is the next phase's work, under its own rules. Showing it here would have
demonstrated the same facts with the client's data in the blast radius.

## 7. Methodology

Each finding was treated as a hypothesis, tested against the live slice of the
estate, and given a verdict from what came back, never from a banner or a version
string. HTTP proofs use a session per principal and send a matched control
alongside every probe, so a change in behaviour can be attributed to the input
rather than to noise. The socket proofs speak the line protocol directly. The TLS
proof attempts the weak window itself and reports what the service agreed to.

Every script is standalone, takes `--target`, prints one JSON verdict and keeps
diagnostics off stdout, so the evidence can be replayed. Nothing was run through
`sqlmap` or any other exploitation framework: the verdicts are the analyst's logic,
which is the competency the client is paying for.

Limits worth stating. The estate verified is a slice, not the whole platform. The
synthetic principals are members only, so anything requiring an approver or an
administrator stays unconfirmed. Where the live slice was not reachable from the
analysis host used for a given run, the script records `unconfirmed` with the access
it needs instead of promoting the claim.

