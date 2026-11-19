# Stop-points per class (neutral)

  SQL injection         prove a true/false, time or error differential; stop
                        before ANY data extraction.
  XSS                   prove a benign marker reaches executable context; stop
                        before a weaponised payload.
  Broken access control prove ONE unauthorized object; stop before enumeration.
  Path traversal        read the benign marker outside the root; stop before any
                        sensitive file.
  Service vulnerability elicit the behavioural tell; stop before running the
                        exploit; use `unconfirmed` if access is lacking.
  TLS / configuration   show what the service negotiates; stop before
                        interception.
  Business logic        minimal reproducible proof; stop before demonstrating
                        impact.
