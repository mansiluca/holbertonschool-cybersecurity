# 13x01 Ground Truth — Task 7: tree, timeline and verdicts

FLAG_PARENT: C:\Windows\System32\wscript.exe (ProcessGuid {bd691e28-1800-4e04-8f79-9ee12aeb3956}), spawned by C:\Windows\explorer.exe, running C:\Users\sdumont\Downloads\PORTWAY-DISPATCH-UPDATE.js
FLAG_PERSIST: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Tavistock9 -> C:\Users\sdumont\AppData\Roaming\iblenor.exe
FLAG_PAYLOAD: C:\Users\sdumont\AppData\Roaming\iblenor.exe
FLAG_C2: 198.51.100.47 (cdn-halcyon-sync.example) tcp/443

## Tree (agent 001, PORTWAY-WS-114, every edge backed by one event)

```
explorer.exe (pid 17140, PORTWAY\sdumont)
  └─ EID 1  wscript.exe (pid 19308, {bd691e28-...})   Downloads\PORTWAY-DISPATCH-UPDATE.js
     └─ EID 1  powershell.exe (pid 19312, {a0e0be61-...})   -nop -w hidden -enc, Medium
        ├─ EID 11  writes C:\Users\sdumont\AppData\Roaming\iblenor.exe
        ├─ EID 13  sets HKCU\...\Run\Tavistock9 -> iblenor.exe
        └─ EID 1   iblenor.exe (pid 19332, {ec443170-...})
              └─ EID 3  tcp/443 -> 198.51.100.47 (cdn-halcyon-sync.example)

separate chain, administrative, cleared:
nmdeploy-agent.exe (C:\Program Files\Northmoor\DeployAgent\, PORTWAY\svc_nmdeploy, pid 1340)
  └─ EID 1  powershell.exe (pid 19292, {5891c7e0-...})  -EncodedCommand Northmoor\stage\pkg_7708.ps1, High
     └─ EID 3  internal only: 10.42.8.2, 10.42.8.10, 10.42.8.20, 10.42.8.30
```

## Timeline (host time, 2026-09-18)

| time | event | meaning |
|---|---|---|
| 07:55:00.000 | EID 1 explorer.exe -> wscript.exe (pid 19308) | the user runs the lure from Downloads |
| 07:55:03.212 | EID 1 wscript.exe -> powershell.exe (pid 19312) | script host hands off to the interpreter |
| ~07:55 | EID 11 powershell writes AppData\Roaming\iblenor.exe | payload lands in a user-writable path |
| 07:55:14.051 | EID 13 Run\Tavistock9 -> iblenor.exe | persistence registered |
| 15:40:12.331 | EID 1 nmdeploy-agent.exe -> powershell (pid 19292) | legitimate deployment, unrelated |
| 16:15:33.738 | EID 3 iblenor.exe -> 198.51.100.47:443 | the callback |

## Node verdicts

### wscript.exe, pid 19308, {bd691e28-...} — MALICIOUS — confidence HIGH
- Decisive artefact: EID 1 of {bd691e28-...}, commandLine
  `WScript.exe ...\Downloads\PORTWAY-DISPATCH-UPDATE.js`, 07:55:00.
- provenance: signed Microsoft script host, the cover, not the finding.
- lineage: parentImage `C:\Windows\explorer.exe`, pid 17140: a human double-click,
  not a service and not a scheduler.
- behaviour: a script interpreter executing a `.js` out of `Downloads`.
- network: no EID 3 attributed to this ProcessGuid.

### powershell.exe, pid 19312, {a0e0be61-...} — MALICIOUS — confidence HIGH
- Decisive artefact: EID 13 from this ProcessGuid,
  `HKCU\...\Run\Tavistock9 -> ...\AppData\Roaming\iblenor.exe`, 07:55:14.051.
- provenance: MD5 121E1253E10DBE8D2D06AAE33EDBC859, identical to the administrator's
  interpreter. It decides nothing, which is the point of the case.
- lineage: parentImage `wscript.exe` ({bd691e28-...}), a lure chain.
- behaviour: `-nop -w hidden -enc`, plus the two writes above.
- network: none under this ProcessGuid.

### iblenor.exe, pid 19332, {ec443170-...} — MALICIOUS — confidence HIGH
- Decisive artefact: EID 3, destinationIp 198.51.100.47, tcp/443, 16:15:33.738.
- provenance: `AppData\Roaming\iblenor.exe`, unsigned, in a user-writable path.
- lineage: it is the run-key target written by {a0e0be61-...}.
- behaviour: `initiated: true`, an outbound connection at process start.
- network: destination is public, not RFC1918, and matches the domain in the beacon.

### pkg_7714, pid 19348, {49fb0168-6c51-42f0-96fe-e45280d8b907} — MALICIOUS — confidence MEDIUM before task 8, HIGH after
- Decisive artefact, before: none in lineage. A deployment-shaped process, a
  service account, a package log, and a command line that fits both stories.
- Decisive artefact, after: EID 3 from this ProcessGuid to 198.51.100.47
  (cdn-halcyon-sync.example), 2026-09-18 13:00:01. A deployment package talking to
  the same external endpoint as the implant is not a deployment package.
- provenance: `PORTWAY\svc_nmdeploy`, log `C:\ProgramData\Northmoor\logs\pkg_7714.log`.
- lineage: odd, which is why this node resisted; see 8-flag.txt.
- behaviour: network egress to the attacker endpoint.
- network: the factor that settled it.

### PORTWAY-DISPATCH-UPDATE.js delivery — UNRESOLVED — confidence LOW
- Decisive artefact: EID 11 file-create of the `.js` under `Downloads`.
- provenance: no signer, no source recorded for the write.
- lineage: the writing process of that EID 11 is not in the telemetry.
- behaviour: execution is proven (see wscript above); arrival is not.
- network: no EID 3 download event corresponds to the file.
- What would settle it: the EID 11 writer image, a mail gateway record, or an
  EID 22 DNS query resolved before the file appeared.

### powershell.exe, pid 19292, {5891c7e0-...} — BENIGN ADMINISTRATIVE — confidence HIGH
- Decisive artefact: EID 1 with `ParentImage C:\Program Files\Northmoor\DeployAgent\nmdeploy-agent.exe`,
  parent user `PORTWAY\svc_nmdeploy`.
- provenance: signed Northmoor stage script `pkg_7708.ps1`.
- lineage: the deployment service, routine on this host.
- behaviour: `integrityLevel High`, no Run-key write under this ProcessGuid.
- network: internal only, `10.42.8.0/24`; never the C2.

## The shared-tool trap

Both interpreters carry the same image and the same MD5. Provenance therefore
tells you nothing about either node, and any rule or verdict keyed to
`powershell.exe` scores them identically. Lineage (a Downloads lure versus a
signed service parent), behaviour (a Run key pointing at `AppData` versus none)
and network (an external C2 versus internal infrastructure) are the only factors
that separate them.

## C2 familiarity

`cdn-halcyon-sync.example` is not new to me. The `cdn-*-sync.example` naming and
the "halcyon" token match infrastructure from a prior engagement at Halcyon Cloud,
where a payload beaconed to the same pattern out of a user-writable path. That is
an actor overlap worth flagging: the same people are working both clients, and
the next case should start by looking for this endpoint rather than ending there.
