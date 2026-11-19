# Verdict schema (neutral)

Every script prints exactly one JSON object on stdout (Task 8 prints a JSON
array of two). Required keys:

  finding      the finding id (e.g. F-WEB-014, or DISCOVERED-001 for task 9)
  class        the vulnerability class you tested
  verdict      confirmed | false_positive | unconfirmed
  evidence     an object with the reproducible observations behind the verdict
  stopped_at   the exact point you stopped (presence/reachability, not impact)

If verdict is `unconfirmed`, also include `to_settle`: what access or testing
would resolve it. Diagnostics go to stderr, never stdout.
