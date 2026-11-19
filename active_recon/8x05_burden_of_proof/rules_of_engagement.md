# Rules of Engagement (signed)

Authorised: active verification of the prior findings against the live Halcyon
targets; proving presence and reachability with minimal, reproducible proofs.

Forbidden: exploitation for impact of any kind - dumping a database, enumerating
a table, stealing a session, executing commands, reading secrets, modifying
another principal's data, crashing a service, intercepting traffic. Each task
states its stop-point; record it in the script's `stopped_at`. Never promote
"could not reproduce" to "false positive"; use `unconfirmed` with `to_settle`.
