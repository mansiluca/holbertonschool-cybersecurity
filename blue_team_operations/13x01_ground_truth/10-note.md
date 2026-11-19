# 13x01 note

**Chain.** `explorer.exe` (pid 17140) spawned `wscript.exe` (pid 19308) running
`C:\Users\sdumont\Downloads\PORTWAY-DISPATCH-UPDATE.js` at 07:55:00; it spawned
`powershell.exe` (pid 19312, `-nop -w hidden -enc`) at 07:55:03.212; that wrote
`C:\Users\sdumont\AppData\Roaming\iblenor.exe` (EID 11), SHA-256
`d13e0265140f33bc79de76e6c31708138443510e9d44184f5acd44ea7a88c6b2`, and set
`HKCU\...\Run\Tavistock9` (EID 13) at 07:55:14.051; `iblenor.exe` (pid 19332) then beaconed to
`198.51.100.47` / `cdn-halcyon-sync.example:443` (EID 3) at 16:15:33.738.

**Hard node.** `pkg_7714` (pid 19348, `PORTWAY\svc_nmdeploy`) fitted a loader and an installer
equally. I predicted malicious if it reached `198.51.100.47`, benign if only `10.42.8.0/24`. EID 3
to `198.51.100.47` at 13:00:01 settled it: malicious. My malicious prediction landed.

**Cleared.** `nmdeploy-agent.exe` -> `powershell.exe` (pid 19292, `pkg_7708.ps1`) is benign on
provenance (signed parent under `Program Files`, not a user opening a `.js`) and network (EID 3
only to `10.42.8.0/24`, never to `198.51.100.47`). Check the parent and every destination; either
test failing voids the clearance.

**Containment, three actions.**

1. Disable `HKCU\...\Run\Tavistock9`. Stops re-execution at logon. Interrupts the operator's
   dispatch client, which must now start by hand for a shift. Costs visibility on whether the
   adversary re-persists the same way.
2. Block `cdn-halcyon-sync.example` and `198.51.100.47:443` at egress. Stops the control channel.
   Interrupts a change window, and a wildcard rule would break neighbouring CDN names, so use the
   exact host and IP. Costs successful check-ins, though blocked attempts still log.
3. Isolate `PORTWAY-WS-114` keeping remote management. Stops lateral movement. Interrupts the
   dispatch shift on that station. Costs live telemetry.

**Fourth slot, rejected by comparison:** memory capture and live response instead of re-imaging.
Lower urgency (nothing in memory stops the attacker tonight, while 1 and 2 act in minutes), lower
risk reduction (collection explains, isolation contains), and partly redundant (hash on EID 11,
chain on EID 1, destination on EID 3). Trading 3 for it would lose more than it gains.

**Cut or watch:** watch, one shift, with action 2 in place now and action 3 held until shift
change. A second-stage fetch, an EID 3 into another internal subnet, or a second host resolving
the C2 domain ends the watching and isolates immediately.
