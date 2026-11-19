# Target map (neutral)

  http://app.halcyon.example:8080
    /login  /dashboard  /preview  /search  /reflect  /files
    /api/v1/profile  /api/v1/lookup  /api/v1/invoices/<id>
    /api/v1/payroll/preview  /api/v1/team/actions  /api/v1/team/actions/approve
  tcp  halcyon.example:16379   line-oriented diagnostic service
  tls  halcyon.example:8443    gateway TLS endpoint
  http halcyon.example:8444    legacy gateway (/legacy-normalize-check, /status)

Which endpoint settles which finding, and whether the claim holds, is for you to
establish by testing. Add app.halcyon.example / halcyon.example to /etc/hosts if
they are not already resolvable (they are inside the lab).
