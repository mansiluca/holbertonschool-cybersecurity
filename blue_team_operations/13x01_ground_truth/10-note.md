# 13x01 Ground Truth - investigation note, PORTWAY-WS-114

## What happened

**Entry, 2026-09-18 07:55:00.** explorer.exe (pid 17140, PORTWAY\sdumont) spawned
wscript.exe (pid 19308, ProcessGuid {bd691e28-1800-4e04-8f79-9ee12aeb3956}) running
C:\Users\sdumont\Downloads\PORTWAY-DISPATCH-UPDATE.js. The lure was named like a
dispatch software update, which is what a dispatch workstation is expected to install.

**Execution, 07:55:03.212.** That script host spawned powershell.exe (pid 19312,
ProcessGuid {a0e0be61-dffb-40af-9c7b-f0a6c40d4ea5}) with -nop -w hidden -enc: no profile,
no window, an encoded payload.

**Persistence, 07:55 and 07:55:14.051.** The same interpreter wrote
C:\Users\sdumont\AppData\Roaming\iblenor.exe (EID 11) and registered it for autorun as
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Tavistock9 (EID 13).

**Callback, 16:15:33.738.** iblenor.exe (pid 19332, ProcessGuid
{ec443170-b1e2-483e-9b49-c60d87f37252}) opened an outbound connection to 198.51.100.47
tcp/443, resolving as cdn-halcyon-sync.example.

Artefacts, by identifier: agent 001 on PORTWAY-WS-114; lure
C:\Users\sdumont\Downloads\PORTWAY-DISPATCH-UPDATE.js; payload
C:\Users\sdumont\AppData\Roaming\iblenor.exe with its EID 11 hash; run value Tavistock9;
C2 198.51.100.47 / cdn-halcyon-sync.example:443; ProcessGuids {bd691e28-...},
{a0e0be61-...}, {ec443170-...}. Process names and the powershell.exe hash
121E1253E10DBE8D2D06AAE33EDBC859 are shared with legitimate activity and identify nothing
on their own.

## The node I had to work for

pkg_7714, pid 19348, ProcessGuid {49fb0168-6c51-42f0-96fe-e45280d8b907}, running as
PORTWAY\svc_nmdeploy with a Northmoor package log at C:\ProgramData\Northmoor\logs\pkg_7714.log.
Its lineage fits a malicious loader and a legitimate installer equally well, so the tree
could not settle it.

What I predicted would settle it, malicious: an EID 3 to 198.51.100.47, since a deployment
package has no reason to reach the attacker endpoint. Benign: EID 3 only to internal hosts
on 10.42.8.0/24, as the genuine package pkg_7708 does, plus a validating Northmoor manifest.
Confidence before looking: no better than 60/40 against.

What settled it: EID 3 by {49fb0168-6c51-42f0-96fe-e45280d8b907} to 198.51.100.47, tcp/443,
at 13:00:01 on 2026-09-18. Verdict malicious, confidence high. My malicious prediction was
the one that landed; that does not make the benign prediction foolish, it simply did not
happen, and the difference between the two packages is that one connection.

## What I cleared

Portway's IT runs nmdeploy-agent.exe from C:\Program Files\Northmoor\DeployAgent\ as
svc_nmdeploy at High integrity, spawning powershell.exe (pid 19292, ProcessGuid
{5891c7e0-8bcc-40fb-96c2-d692884504ac}) with an encoded command and the signed stage script
pkg_7708.ps1.

It is benign on two grounds somebody can test. Provenance: the parent is a signed service
binary under Program Files launched by the deploy service, not a user's double-click on a
file in Downloads. Network: every EID 3 under {5891c7e0-...} goes to 10.42.8.0/24
(10.42.8.2, 10.42.8.10, 10.42.8.20, 10.42.8.30) and never to 198.51.100.47. It writes no Run
key either, because a deployment tool does not need to survive a reboot on its own. Pull the
ProcessGuid, check the EID 1 parent and every EID 3 destination: if either test fails, the
clearance fails.

## Containment: three actions

**Action 1. Disable the autorun value HKCU\...\Run\Tavistock9, after exporting the key for
evidence.**
- Stops: iblenor.exe returning at the next logon.
- Business impact: none tonight; the user's session and the dispatch software are untouched.
- Visibility lost: whether the adversary re-establishes persistence by the same primitive.
- Why it ranks first: it costs nothing, it removes a mechanism we already have the artefact
  for, and it does not tip the adversary off.

**Action 2. Block cdn-halcyon-sync.example and 198.51.100.47:443 at the egress gateway,
organisation-wide.**
- Stops: this implant and any sibling copy calling home.
- Business impact: none; nothing legitimate resolves there.
- Visibility lost: the beacon's successful check-ins.
- Why it ranks second: blocking still logs each attempt, so I keep the timing signal while
  removing the adversary's ability to work, and every other Portway workstation becomes a
  detector for the same infrastructure.

**Action 3. Isolate PORTWAY-WS-114 at the switch, keeping remote management access.**
- Stops: lateral movement off a host with an interactive intrusion.
- Business impact: a dispatch workstation's shift, which is a business cost and not an IT
  one if it is the only station on that shift.
- Visibility lost: live telemetry from the host.
- Why it ranks third: it is the only action with a real business cost, and it is only worth
  that cost once a trigger fires. Doing it first would buy safety with the view I need.

**Fourth action with a fourth slot:** memory capture of iblenor.exe and live response
collection instead of re-imaging. It ranked last because it is slow, needs a tool nobody has
deployed on this estate, and adds mostly attribution value: hashes are already on the EID 11,
the chain is already in EID 1, the destination is already in EID 3. It improves the answer to
who and how far, not the answer to what is running now.

## Cut now or watch

My call: watch, bounded to one shift, with a decision at the end of it. Cut the C2 at the
network now, leave the host running and monitored, and hold isolation until shift change
unless a trigger fires.

Cutting the beacon ends the exposure and ends the view in the same moment. I would stop
seeing whether the implant fetches a second stage and which other hosts it reaches, and that
second question is the one Dana will be asked tomorrow: not whether this host fell, but how
far they got. A blocked destination plus live persistence gives me the attempts without the
capability.

Triggers that end the watching: a second-stage fetch attempt, any EID 3 from this host to
another internal subnet, or a second workstation resolving cdn-halcyon-sync.example. Any of
those and I isolate immediately, because at that point containment beats the view. If nothing
fires, isolate and re-image at shift change with the artefacts already in hand.
