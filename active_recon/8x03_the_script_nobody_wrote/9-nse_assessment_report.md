# NSE Assessment Report, Talvi Systems
For: Ridgeline engagement team

## 1. Executive summary

The built-in `vuln` category reported nothing on Talvi Systems. It reported
nothing because it had nothing to say: the finding lives in a bespoke
management daemon on 9700 that speaks a line-oriented protocol no built-in
script knows, so `-sV` could not name it and the default scripts passed over it
in silence. Eight scripts written for this target fingerprint the service
(`Talvi Management Service 2.1.7`, exposed as `talvi-mgmt`), confirm by
behaviour that its command interface answers a privileged probe with no
authentication at all, and audit one valid credential (`svc-monitor`) without
locking a single account. One more service, the backport gateway on 8443, was
cleared rather than accused. Together the suite shows a full management access
path that a script-runner would have missed entirely.

## 2. The scripts

| Script | Library or pattern | Re-run |
|---|---|---|
| `1-modify_detect.nse` | `http`, modified built-in header probe | `nmap -sT -Pn --script ./1-modify_detect.nse -p 8080 talvi.example` |
| `2-svc_discovery.nse` | `shortport`, raw socket, `stdnse.output_table` | `nmap -sT -Pn --script ./2-svc_discovery.nse -p 9700 talvi.example` |
| `3-talvi_version.nse` | custom protocol, `nmap.set_port_version`, registry | `nmap -sT -Pn --script ./3-talvi_version.nse -p 9700 talvi.example` |
| `4-talvi_vuln.nse` | `vulns` with behavioural confirmation | `nmap -sT -Pn --script ./4-talvi_vuln.nse -p 9700 talvi.example` |
| `5-vuln_state.nse` | `vulns`, version match plus negative behaviour probe | `nmap -sT -Pn --script ./5-vuln_state.nse -p 8443 talvi.example` |
| `6-brute_driver.nse` | `brute` Driver, `creds`, `unpwdb` | `nmap -sT -Pn --script ./6-brute_driver.nse -p 9700 talvi.example` |
| `7-brute_lockout.nse` | Driver bounded by the served lockout policy | `nmap -sT -Pn --script ./7-brute_lockout.nse -p 9700 talvi.example` |
| `8-consolidate.nse` | `postrule` reading `nmap.registry` | run with 3, 4 and 6 in one scan |

## 3. Findings

- **Management console build tag** — `TALVI-MGMT-1.4`, served in the
  `X-Talvi-Build` header and repeated in a `talvi-build` meta tag on 8080.
- **Bespoke service fingerprinted** — `TALVI-MGMT ready` greeting on 9700, then
  `Talvi Management Service` version `2.1.7`. The version script sets the port
  version so the engine names the service `talvi-mgmt` itself.
- **Vulnerability confirmed (VULN)** — the unauthenticated command interface.
  `VULN-CHECK` is answered `PRIVILEGED-PROBE accepted-without-auth` and
  `NO-COMMAND-EXECUTED`, before any `AUTH`. Confirmed by behaviour, so `VULN`.
- **Credential audited** — `svc-monitor` on 9700, found with one failed attempt
  on the account. A second, lockout-aware run recovered `backup-admin` with
  three failed attempts against a threshold of five, no lockout triggered.
- **Backport gateway cleared** — version `4.2.0` matches the published advisory
  range, but the behaviour probe was negative: reported `LIKELY_VULN`, not
  `VULN`.
- **Consolidated result** — `Talvi-MGMT 2.1.7` on 9700 with a confirmed command
  interface plus a valid `svc-monitor` credential is a full management access
  path: the interface is reachable unauthenticated and the credential is
  valid on it.

## 4. Vulnerability states (VULN vs LIKELY_VULN)

| Finding | State | Why |
|---|---|---|
| Unauthenticated command interface on 9700 | `VULN` | Behaviour confirmed: privileged probe accepted without auth |
| Backport gateway 4.2.0 on 8443 | `LIKELY_VULN` | Version string matches the advisory, behaviour probe negative |
| Everything version-only | `LIKELY_VULN` | A version string is a suspicion, never a proof |

No finding carries `EXPLOIT`. The Rules of Engagement authorise confirmation,
not exploitation, and an `EXPLOIT` state would mean a command was actually run
on the client's fleet. It was not. The distinction matters to the client
because it is the difference between "spend money on this now" and "this looks
like the advisory, verify before you act": a backported build keeps its version
number, so a version-only verdict would have accused a patched service and
wasted the remediation budget.

## 5. Methodology and limitations

What was confirmed: the service identity and version, the unauthenticated
command interface by behaviour, two valid credentials by authentication,
the lockout policy (threshold five attempts, window sixty seconds) and the
behavioural absence of the gateway flaw.

What was identified but not exploited: the command interface itself. The safe
probe executes nothing, and no destructive or state-changing command was sent.
No exploitation phase was performed, by design.

What could still hide: the protocol advertises capabilities, and only
`VULN-CHECK` was exercised; any privileged function behind a successful `AUTH`
is out of scope here and belongs to the next phase. The web console on 8080 was
only read for its build tag. `talvi.example` resolves to the lab workstation
itself, so nothing here says anything about the production estate: the next
phase must re-run this suite against the real addresses.
