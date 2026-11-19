# 13x01 Ground Truth — Task 10: investigation note, PORTWAY-WS-114

## What happened

The attack is four steps.

1. **Entry, 2026-09-18 07:55:00.** `C:\Windows\explorer.exe` (pid 17140, `PORTWAY\sdumont`)
   spawned `C:\Windows\System32\wscript.exe` (pid 19308, ProcessGuid
   `{bd691e28-1800-4e04-8f79-9ee12aeb3956}`) with the command line
   `WScript.exe ...\Downloads\PORTWAY-DISPATCH-UPDATE.js`. The lure was named like a
   dispatch software update, which is exactly what a dispatch workstation is expected
   to install.
2. **Execution, 07:55:03.212.** That script host spawned `powershell.exe` (pid 19312,
   ProcessGuid `{a0e0be61-dffb-40af-9c7b-f0a6c40d4ea5}`) with `-nop -w hidden -enc`:
   no profile, no window, an encoded payload.
3. **Persistence, 07:55 and 07:55:14.051.** The same interpreter wrote
   `C:\Users\sdumont\AppData\Roaming\iblenor.exe` (EID 11) and then registered it for
   autorun as `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Tavistock9` (EID 13).
   The implant now returns at every logon without touching a service.
4. **Callback, 16:15:33.738.** `iblenor.exe` (pid 19332, ProcessGuid
   `{ec443170-b1e2-483e-9b49-c60d87f37252}`) opened an outbound connection to
   `198.51.100.47` tcp/443, resolving as `cdn-halcyon-sync.example`.

No toolkit was installed and none was needed: the signed interpreter every Windows
host carries did the work, the payload lived in a user's own profile, and
persistence was one registry value. The artefacts to pin are the lure
`C:\Users\sdumont\Downloads\PORTWAY-DISPATCH-UPDATE.js`, the payload
`C:\Users\sdumont\AppData\Roaming\iblenor.exe` (unsigned, hash captured on the EID 11),
the run key `Tavistock9`, the C2 `198.51.100.47` (`cdn-halcyon-sync.example`), and the
two malicious ProcessGuids above. Process names and the interpreter hash are shared
with legitimate activity and identify nothing on their own.

## The node I had to work for

`pkg_7714`, pid 19348, ProcessGuid `{49fb0168-6c51-42f0-96fe-e45280d8b907}`, running as
`PORTWAY\svc_nmdeploy` with a Northmoor package log at
`C:\ProgramData\Northmoor\logs\pkg_7714.log`. Lineage says nothing useful: a service
account and a deployment-shaped parent fit a malicious loader and a legitimate
installer equally well, and staring at the tree harder was never going to settle it.

Before going looking, I wrote down what would settle it in each direction. Malicious:
any EID 3 from that ProcessGuid to `198.51.100.47`, because a deployment package has no
business talking to the attacker's endpoint. Benign: EID 3 only to internal Portway
hosts on `10.42.8.0/24`, the pattern the genuine package `pkg_7708` shows, plus a
validating Northmoor manifest. My confidence at that point was no better than 60/40
against.

What I found was a connection to `198.51.100.47` on tcp/443 at 2026-09-18 13:00:01.
Verdict MALICIOUS, confidence high. The malicious prediction was the one that landed;
the benign prediction was not stupid, it simply did not happen, and the difference
between the two packages is exactly that one connection. The factor that settled it
was network, not lineage.

## What I cleared

Portway's IT genuinely runs a chain on this host that uses the same interpreter and
looks guilty: `nmdeploy-agent.exe` under `C:\Program Files\Northmoor\DeployAgent\`,
running as `svc_nmdeploy` at High integrity, spawning `powershell.exe` (pid 19292,
ProcessGuid `{5891c7e0-8bcc-40fb-96c2-d692884504ac}`) with an encoded command and the
signed stage script `pkg_7708.ps1`.

Provenance clears it: the parent is a signed service binary under `Program Files`
launched by the deploy service, not a user's double-click on a file in `Downloads`.
Network clears it: every EID 3 under that ProcessGuid goes to internal hosts on
`10.42.8.0/24` (`10.42.8.2`, `10.42.8.10`, `10.42.8.20`, `10.42.8.30`), and it never
touches `198.51.100.47`. It also never writes a Run key, because a deployment tool does
not need to survive a reboot by itself. Anybody can falsify that: take the ProcessGuid,
pull the EID 1 parent and every EID 3 destination. If either test fails, the clearance
fails.

## Containment: three actions

1. **Disable the autorun value `HKCU\...\Run\Tavistock9`**, exporting the key first for
   evidence. Stops: the implant returning at next logon. Business cost: none tonight,
   the user's session is untouched. Visibility cost: I lose the signal of whether the
   adversary re-establishes persistence the same way.
2. **Block `cdn-halcyon-sync.example` and `198.51.100.47:443` at the egress gateway**,
   organisation-wide. Stops: this implant and any sibling copy calling home. Business
   cost: none, nothing legitimate resolves there. Visibility cost: the beacon itself,
   since failures tell me less than successes did.
3. **Isolate `PORTWAY-WS-114` at the switch, keeping remote management access.** Stops:
   lateral movement off a host with an interactive intrusion. Business cost: a dispatch
   workstation's shift, which is a business cost and not an IT one if it is the only
   station on that shift. Visibility cost: live telemetry from the host, which is why I
   would rather do it deliberately than reflexively.

With a fourth slot I would take a memory capture of `iblenor.exe` and live response
collection instead of re-imaging. It lost because it is slow, it needs a tool nobody has
deployed on this estate yet, and the artefacts I need are already in telemetry: hashes
on EID 11, the ProcessGuid chain on EID 1, the destination on EID 3. Collection adds
what the implant holds in memory, which matters for attribution and for finding other
hosts, not for stopping this one.

## Cut now or watch

My call: **watch, for one shift, with a decision at the end of it.** Cut the C2 at the
network now, leave the host running and monitored, and hold the isolation decision until
shift change unless a trigger fires.

Cutting the beacon ends the exposure and ends my view in the same moment. I stop seeing
what the implant tries next, whether it fetches a second stage, and which other hosts it
talks to. That last question is the one Dana will be asked tomorrow: not whether this
host was compromised, but how far they got. Blocking the destination while leaving the
persistence in place lets them keep trying and keeps failing, and the failures are
evidence.

The triggers that end the watching: a second-stage fetch attempt, any EID 3 from this host
to another internal subnet, or a second workstation appearing with the same destination.
Any of those and I isolate immediately, because at that point containment beats the view.
If nothing fires in the window, I isolate and re-image with the artefacts in hand and the
answer to the question that actually matters.
