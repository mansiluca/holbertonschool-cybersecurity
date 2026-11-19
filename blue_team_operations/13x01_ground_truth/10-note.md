# 13x01 Ground Truth - investigation note, PORTWAY-WS-114

## What happened

**1. Entry.** On 2026-09-18 at 07:55:00, `explorer.exe` (pid 17140, `PORTWAY\sdumont`) spawned
`C:\Windows\System32\wscript.exe` (pid 19308, ProcessGuid
`{bd691e28-1800-4e04-8f79-9ee12aeb3956}`) with the command line
`WScript.exe ...\Downloads\PORTWAY-DISPATCH-UPDATE.js`. The lure was named like a dispatch
software update, which is exactly what a dispatch workstation is expected to install. The
script host is a decoy in this tree, not the origin.

**2. Execution.** At 07:55:03.212 that script host spawned `powershell.exe` (pid 19312,
ProcessGuid `{a0e0be61-dffb-40af-9c7b-f0a6c40d4ea5}`) with `-nop -w hidden -enc`: no profile,
no window, a Base64-encoded command (T1059.001). This stage is the writer.

**3. Payload drop.** EID 11 recorded `C:\Users\sdumont\AppData\Roaming\iblenor.exe`,
SHA-256 `d13e0265140f33bc79de76e6c31708138443510e9d44184f5acd44ea7a88c6b2`, written into a
user-writable path that needs no privilege.

**4. Persistence.** At 07:55:14.051, EID 13 recorded
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Tavistock9` pointing at that same
image (T1547.001), so the implant returns at `sdumont`'s next logon without touching HKLM or
asking for elevation.

**5. Callback.** `iblenor.exe` (pid 19332, ProcessGuid
`{ec443170-b1e2-483e-9b49-c60d87f37252}`) opened EID 3 connections to `198.51.100.47`
(`cdn-halcyon-sync.example`) over tcp/443 at 16:15:33.738, on a steady interval (T1071.001).
A regular cadence to one external host is the beacon.

Artefacts by identifier: agent 001 on PORTWAY-WS-114; lure
`C:\Users\sdumont\Downloads\PORTWAY-DISPATCH-UPDATE.js`; payload
`C:\Users\sdumont\AppData\Roaming\iblenor.exe`, SHA-256
`d13e0265140f33bc79de76e6c31708138443510e9d44184f5acd44ea7a88c6b2`; run value `Tavistock9`;
C2 `198.51.100.47` / `cdn-halcyon-sync.example:443`; ProcessGuids `{bd691e28-...}`,
`{a0e0be61-...}`, `{ec443170-...}`. The interpreter image and its MD5
`121E1253E10DBE8D2D06AAE33EDBC859` are shared with legitimate activity and identify nothing.

## The node I had to work for

`pkg_7714`, pid 19348, ProcessGuid `{49fb0168-6c51-42f0-96fe-e45280d8b907}`, running as
`PORTWAY\svc_nmdeploy` with a package log at `C:\ProgramData\Northmoor\logs\pkg_7714.log`.
Its lineage fits a malicious loader and a legitimate installer equally well, so the tree could
not settle it.

Before looking, I wrote down what would settle it in each direction. Malicious: an EID 3 to
`198.51.100.47`, because a deployment package has no reason to reach the attacker endpoint.
Benign: EID 3 only to internal hosts on `10.42.8.0/24` as the genuine package `pkg_7708` does,
plus a validating Northmoor manifest. My confidence was no better than 60/40 against.

What settled it: EID 3 by `{49fb0168-...}` to `198.51.100.47` tcp/443 at 13:00:01. Verdict
malicious, confidence high. My malicious prediction was the one that landed. The benign
prediction was not foolish, it simply did not happen, and the difference between the two
packages is that single connection.

## What I cleared

Portway's IT runs `nmdeploy-agent.exe` from `C:\Program Files\Northmoor\DeployAgent\` as
`svc_nmdeploy` at High integrity, spawning `powershell.exe` (pid 19292, ProcessGuid
`{5891c7e0-8bcc-40fb-96c2-d692884504ac}`) with an encoded command and the signed stage script
`pkg_7708.ps1`.

It is benign on two grounds somebody can test. Provenance: the parent is a signed service
binary under `Program Files` launched by the deploy service, not a user's double-click on a file
in `Downloads`. Network: every EID 3 under `{5891c7e0-...}` goes to `10.42.8.0/24`
(`10.42.8.2`, `10.42.8.10`, `10.42.8.20`, `10.42.8.30`) and never to `198.51.100.47`. It writes
no Run key, because a deployment tool does not need to survive a reboot on its own. Pull the
ProcessGuid, check the EID 1 parent and every EID 3 destination: if either test fails, the
clearance fails. It is cleared, not quietly escalated.

## Containment, three actions

Three actions are selected. Each one states what it stops, which legitimate business function it
interrupts, and what evidence or future visibility it costs.

**Action 1, disable the autorun value `HKCU\...\Run\Tavistock9`** after exporting the key for
evidence. It stops iblenor.exe from being re-executed at the next logon, which is the attacker's
only persistence. It interrupts a real business function: the user's dispatch client stops
auto-starting with the profile, so the operator has to launch it by hand for one shift, and the
change has to be recorded on the workstation's configuration baseline. It costs me visibility into
whether the adversary re-establishes persistence by the same primitive, because the value is gone
and a re-creation attempt is what I would otherwise be watching for.

**Action 2, block `cdn-halcyon-sync.example` and `198.51.100.47:443` at the egress gateway.** It
stops the implant, and any sibling copy of it, from calling home, which removes the attacker's
control channel. It interrupts a legitimate business function at the perimeter: the rule has to be
pushed during a change window, and written as a wildcard over `*-sync.example` it would also break
ordinary CDN traffic on neighbouring names, so it must be the exact host and IP. It costs me the
beacon's successful check-ins as evidence, though blocked attempts keep logging timing, and it
turns every other Portway workstation into a detector for the same infrastructure.

**Action 3, isolate `PORTWAY-WS-114` at the switch** while keeping remote management access. It
stops lateral movement off a host that has had an interactive intrusion. It interrupts the dispatch
shift that runs on that station, which is a business cost and not an IT one, and if this is the
only station on the shift then the shift stops rather than slows. It costs me live telemetry from
the host, which is the reason it is the last of the three and not the first.

**Rejected, the fourth action I would have taken with another slot: memory capture of `iblenor.exe`
plus live response collection instead of re-imaging.** It ranked below the three by comparison, not
because the budget ran out. Its urgency is lower: nothing in memory is stopping the attacker
tonight, while actions 1 and 2 change what the attacker can do within minutes and cost the business
nothing. Its risk reduction is lower: collection explains how the implant works and supports
attribution, but it does not contain movement, and isolation already does that better. And its
evidence is partly redundant, because the hash is on the EID 11, the chain on the EID 1 and the
destination on the EID 3. If I were forced to trade one action for it, action 3 would still outrank
it, since containment beats explanation when the beacon is live.

## Cut now or watch

My call is to watch, bounded to one shift, with a decision at the end of it: put action 2 in place
now, leave the host running and monitored, and hold action 3 until shift change unless a trigger
fires.

Cutting the beacon ends the exposure and ends the view in the same moment. I would stop seeing
whether the implant fetches a second stage and which other hosts it reaches, and that second
question is the one Dana will be asked tomorrow: not whether this host fell, but how far they
got. A blocked destination plus live persistence gives me the attempts without the capability.

Triggers that end the watching: a second-stage fetch attempt, any EID 3 from this host into
another internal subnet, or a second workstation resolving `cdn-halcyon-sync.example`. Any of
those and I isolate immediately, because at that point containment beats the view. If nothing
fires, isolate and re-image at shift change with the artefacts already in hand.
