# 8x03 - The Script Nobody Wrote

NSE suite written against Talvi Systems for Ridgeline Security.

## Deliverables

- `1-modify_detect.nse` - modified built-in header probe, surfaces the console build tag
- `2-svc_discovery.nse` - discovery probe on the bespoke protocol
- `3-talvi_version.nse` - version detection and port naming for the bespoke service
- `4-talvi_vuln.nse` - `vulns` script, behavioural confirmation, VULN only
- `5-vuln_state.nse` - honest state: version-only match is LIKELY_VULN
- `6-brute_driver.nse` - `brute` Driver contract with `creds` and `unpwdb`
- `7-brute_lockout.nse` - lockout-aware Driver, bounded by the served policy
- `8-consolidate.nse` - `postrule` consolidation through `nmap.registry`
- `9-nse_assessment_report.md` - assessment report

## Usage

```
nmap -sT -Pn --script ./1-modify_detect.nse -p 8080 talvi.example
nmap -sT -Pn --script ./2-svc_discovery.nse -p 9700 talvi.example
nmap -sT -Pn --script ./3-talvi_version.nse -p 9700 talvi.example
nmap -sT -Pn --script ./4-talvi_vuln.nse -p 9700 talvi.example
nmap -sT -Pn --script ./5-vuln_state.nse -p 8443 talvi.example
nmap -sT -Pn --script ./6-brute_driver.nse -p 9700 talvi.example
nmap -sT -Pn --script ./7-brute_lockout.nse -p 9700 talvi.example
nmap -sT -Pn --script "./3-talvi_version.nse,./4-talvi_vuln.nse,./6-brute_driver.nse,./8-consolidate.nse" -p 9700 talvi.example
```

Wordlists default to `wordlists/task6-*.txt` and `wordlists/task7-*.txt`;
`userdb` and `passdb` override them.

States are honest: `LIKELY_VULN` for a version-only match, `VULN` only on
behavioural confirmation, `EXPLOIT` never. Credential scripts stay below the
lockout threshold served by the target.
