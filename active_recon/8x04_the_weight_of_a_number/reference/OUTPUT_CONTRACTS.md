# Output contracts (neutral)

normalized.json   array of unified findings (Tasks 1-3).
correlated.json   merged findings with merged_id, asset, sources, classification,
                  confidence, cve, service (Tasks 4-5).
triaged.json      correlated fields + triage + signal (Task 6).
verified.json     fields + a verification block {merged_id, verified, evidence,
                  target} (Task 7).
rescored.json     fields + merged_id, asset, vector_version, base, environmental
                  (Task 8).
priority.json /   traceable ranking: rank, merged_id, asset, base, environmental,
priority.csv      kev, epss, confidence, verification, priority, justification
                  (Task 9).

Emit machine-readable output from code; never hand-author the JSON or CSV.
