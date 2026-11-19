# 13x01 Ground Truth - Task 7: tree, timeline, verdicts

FLAG_PARENT: C:\Windows\System32\wscript.exe (ProcessGuid {bd691e28-1800-4e04-8f79-9ee12aeb3956}), parent C:\Windows\explorer.exe, running C:\Users\sdumont\Downloads\PORTWAY-DISPATCH-UPDATE.js
FLAG_PERSIST: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Tavistock9 -> C:\Users\sdumont\AppData\Roaming\iblenor.exe
FLAG_PAYLOAD: C:\Users\sdumont\AppData\Roaming\iblenor.exe
FLAG_C2: 198.51.100.47 (cdn-halcyon-sync.example) tcp/443

## Tree

```
explorer.exe (pid 17140, PORTWAY\sdumont)
  +- EID 1  wscript.exe (pid 19308, {bd691e28-...})   Downloads\PORTWAY-DISPATCH-UPDATE.js
     +- EID 1  powershell.exe (pid 19312, {a0e0be61-...})   -nop -w hidden -enc, Medium
        +- EID 11  writes C:\Users\sdumont\AppData\Roaming\iblenor.exe
        +- EID 13  sets HKCU\...\Run\Tavistock9 -> iblenor.exe
        +- EID 1   iblenor.exe (pid 19332, {ec443170-...})
              +- EID 3  tcp/443 -> 198.51.100.47 (cdn-halcyon-sync.example)

administrative chain, cleared:
nmdeploy-agent.exe (C:\Program Files\Northmoor\DeployAgent\, PORTWAY\svc_nmdeploy, pid 1340)
  +- EID 1  powershell.exe (pid 19292, {5891c7e0-...})  -EncodedCommand Northmoor\stage\pkg_7708.ps1, High
     +- EID 3  internal only: 10.42.8.2, 10.42.8.10, 10.42.8.20, 10.42.8.30
```

## Timeline (host time, 2026-09-18)

| time | event | what it means |
|---|---|---|
| 07:55:00.000 | EID 1 explorer.exe -> wscript.exe (pid 19308) | user runs the lure from Downloads |
| 07:55:03.212 | EID 1 wscript.exe -> powershell.exe (pid 19312) | script host hands off to the interpreter |
| ~07:55 | EID 11 powershell writes AppData\Roaming\iblenor.exe | payload lands in a user-writable path |
| 07:55:14.051 | EID 13 Run\Tavistock9 -> iblenor.exe | persistence registered |
| 15:40:12.331 | EID 1 nmdeploy-agent.exe -> powershell (pid 19292) | legitimate deployment, unrelated |
| 16:15:33.738 | EID 3 iblenor.exe -> 198.51.100.47:443 | the callback |

## Node verdicts

| node | verdict | confidence | decisive artefact |
|---|---|---|---|
| wscript.exe pid 19308 {bd691e28-...} | MALICIOUS | HIGH | EID 1 command line WScript.exe ...\Downloads\PORTWAY-DISPATCH-UPDATE.js at 07:55:00 |
| powershell.exe pid 19312 {a0e0be61-...} | MALICIOUS | HIGH | EID 13 HKCU\...\Run\Tavistock9 -> AppData\Roaming\iblenor.exe at 07:55:14.051 |
| iblenor.exe pid 19332 {ec443170-...} | MALICIOUS | HIGH | EID 3 to 198.51.100.47 tcp/443 at 16:15:33.738, initiated true |
| pkg_7714 pid 19348 {49fb0168-...} | MALICIOUS (after task 8) | MEDIUM then HIGH | EID 3 to 198.51.100.47 (cdn-halcyon-sync.example) at 13:00:01 |
| PORTWAY-DISPATCH-UPDATE.js delivery | UNRESOLVED | LOW | EID 11 file create of the .js: it landed, its writer is not in telemetry |
| powershell.exe pid 19292 {5891c7e0-...} | BENIGN administrative | HIGH | EID 1 parentImage nmdeploy-agent.exe under Program Files\Northmoor, parentUser svc_nmdeploy |

### wscript.exe, pid 19308, {bd691e28-...} - MALICIOUS - HIGH
- provenance: signed Microsoft script host. The signature is the cover, not the finding.
- lineage: parentImage C:\Windows\explorer.exe (pid 17140): a human double-click, not a service, not a scheduler.
- behaviour: a script interpreter executing a .js out of a Downloads folder.
- network: no EID 3 attributed to this ProcessGuid.
- Decisive: EID 1 command line, 07:55:00.

### powershell.exe, pid 19312, {a0e0be61-...} - MALICIOUS - HIGH
- provenance: MD5 121E1253E10DBE8D2D06AAE33EDBC859, identical to the administrator's interpreter. It decides nothing.
- lineage: parentImage wscript.exe ({bd691e28-...}), a lure chain rather than a service.
- behaviour: -nop -w hidden -enc, plus the EID 11 write and the EID 13 Run-key set.
- network: none under this ProcessGuid.
- Decisive: EID 13, 07:55:14.051.

### iblenor.exe, pid 19332, {ec443170-...} - MALICIOUS - HIGH
- provenance: AppData\Roaming, unsigned, user-writable path.
- lineage: it is the value the Run key was pointed at by {a0e0be61-...}.
- behaviour: outbound connection at process start, initiated true.
- network: destination 198.51.100.47 is public, not RFC1918, and matches the beacon domain.
- Decisive: EID 3, 16:15:33.738.

### pkg_7714, pid 19348, {49fb0168-6c51-42f0-96fe-e45280d8b907} - MALICIOUS - MEDIUM at first sight, HIGH after task 8
- provenance: PORTWAY\svc_nmdeploy, log C:\ProgramData\Northmoor\logs\pkg_7714.log.
- lineage: odd; this is the node that resists lineage, and the tree cannot settle it.
- behaviour: deployment-shaped, so it fits both stories.
- network: EID 3 to 198.51.100.47 (cdn-halcyon-sync.example), 2026-09-18 13:00:01. A deployment package does not talk to the implant's endpoint.
- Decisive: that one connection, found in task 8.

### PORTWAY-DISPATCH-UPDATE.js delivery - UNRESOLVED - LOW
- provenance: no signer and no source recorded for the write.
- lineage: the writing process of the EID 11 is not in the telemetry.
- behaviour: execution is proven; arrival is not.
- network: no EID 3 download event corresponds to the file.
- Would settle it: the EID 11 writer image, a mail gateway record, or an EID 22 DNS query preceding the file.

### powershell.exe, pid 19292, {5891c7e0-...} - BENIGN administrative - HIGH
- provenance: signed Northmoor stage script pkg_7708.ps1.
- lineage: parentImage nmdeploy-agent.exe, the deployment service, routine on this host.
- behaviour: integrityLevel High, no Run-key write under this ProcessGuid.
- network: internal only on 10.42.8.0/24, never the C2.
- Decisive: EID 1 parentImage and parentUser.

## Shared-tool trap

Both interpreters carry the same image and the same MD5, so provenance scores them identically and a rule keyed to powershell.exe cannot tell them apart. Only lineage (Downloads lure versus signed service parent), behaviour (Run key pointing at AppData versus none) and network (external C2 versus internal 10.42.8.0/24) separate them.

## C2 and cross-client recognition

Destination: 198.51.100.47, hostname cdn-halcyon-sync.example, tcp/443, first seen on this host 2026-09-18 16:15:33.738, plus the same endpoint contacted by pkg_7714 at 13:00:01.

It is familiar, and I am saying so rather than filing it as new infrastructure. The cdn-*-sync.example naming and the "halcyon" token match the endpoint a prior engagement at Halcyon Cloud beaconed to, out of the same kind of user-writable drop. That is actor overlap across two clients: same infrastructure pattern, same dwell style, same persistence habit. Consequence for this engagement: hunt the endpoint, not just the host, because a second Portway workstation with this destination is the same operator, and the next case should start from the endpoint rather than end there.
