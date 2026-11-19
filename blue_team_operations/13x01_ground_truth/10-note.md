# 13x01 Ground Truth — Task 10: investigation note, PORTWAY-WS-114

## What happened

The host was compromised from the inside out: a user ran a file they were given,
and everything after that was automatic.

At 07:55:00 on 2026-09-18, `explorer.exe` (pid 17140, `PORTWAY\sdumont`) spawned
`C:\Windows\System32\wscript.exe` (pid 19308, ProcessGuid
`{bd691e28-1800-4e04-8f79-9ee12aeb3956}`) with the command line
`WScript.exe ...\Downloads\PORTWAY-DISPATCH-UPDATE.js`. The lure was named like a
dispatch software update, which is exactly what a dispatch workstation is
expected to install. Three seconds later, at 07:55:03.212, that script host
spawned `powershell.exe` (pid 19312, ProcessGuid `{a0e0be61-dffb-40af-9c7b-f0a6c40d4ea5}`)
with `-nop -w hidden -enc`: no profile, no window, an encoded payload.

That interpreter wrote `C:\Users\sdumont\AppData\Roaming\iblenor.exe` (EID 11),
then at 07:55:14.051 registered it for autorun under
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Tavistock9` (EID 13). At
16:15:33.738 the implant `iblenor.exe` (pid 19332, ProcessGuid
`{ec443170-b1e2-483e-9b49-c60d87f37252}`) opened an outbound connection to
`198.51.100.47` tcp/443, resolving as `cdn-halcyon-sync.example`.

So: entry via a user-executed script lure, execution through the signed
interpreter that every Windows host carries, persistence in the per-user Run key
pointing at a profile directory, and a single callback to an external host. No
tooling was installed. Nothing needed to be installed.

The endpoint artefacts to pin, in one place: the lure
`C:\Users\sdumont\Downloads\PORTWAY-DISPATCH-UPDATE.js`; the payload
`C:\Users\sdumont\AppData\Roaming\iblenor.exe` (unsigned, hash captured on the
EID 11); the persistence value `Tavistock9`; the C2 `198.51.100.47`
(`cdn-halcyon-sync.example`); and the two malicious ProcessGuids above, which are
the only reliable handles on this chain because the process names and the
interpreter hash are shared with legitimate activity.

## The node I had to work for

`pkg_7714` (pid 19348, ProcessGuid
`{49fb0168-6c51-42f0-96fe-e45280d8b907}`) resisted everything the tree offered.
It ran as `PORTWAY\svc_nmdeploy`, it carried a Northmoor package log, it looked
like the deployment step that happens on this host every afternoon. Its lineage
fits a malicious loader and a legitimate installer equally well, so looking harder
at the tree was never going to settle it.

Before going looking I wrote down what would settle it each way. Malicious: any
EID 3 to `198.51.100.47`, because a deployment package has no business talking to
the attacker's endpoint. Benign: EID 3 only to internal Portway hosts on
`10.42.8.0/24`, the pattern the genuine package `pkg_7708` shows, plus a validating
Northmoor manifest. My confidence was no better than 60/40 against.

The connection I found was to `198.51.100.47` on tcp/443 at 2026-09-18 13:00:01.
The predicted-to-be-malicious artefact was the one that landed. The benign
prediction was not wrong to make; it simply did not happen. Verdict MALICIOUS,
confidence now high, and the factor that decided it was network, not lineage.

## What I cleared

Portway's IT genuinely runs a chain on this host that uses the same interpreter,
spawns unusual children and looks guilty: `nmdeploy-agent.exe` under
`C:\Program Files\Northmoor\DeployAgent\`, running as `svc_nmdeploy` at High
integrity, spawning `powershell.exe` (pid 19292, ProcessGuid
`{5891c7e0-8bcc-40fb-96c2-d692884504ac}`) with an encoded command and the signed
stage script `pkg_7708.ps1`.

What clears it is provenance and network, and neither is the tool. The parent is a
signed service binary under `Program Files`, not a user's double-click on a file in
`Downloads`. And every one of its EID 3 connections goes to internal hosts on
`10.42.8.0/24`: `10.42.8.2`, `10.42.8.10`, `10.42.8.20`, `10.42.8.30`. It never
touches `198.51.100.47`, and it never writes a Run key, because a deployment tool
does not need to survive a reboot on its own. Anyone can test that claim: pull the
ProcessGuid, check the EID 1 parent, check every EID 3 destination. If either test
fails, the clearance fails.

## Containment: three actions, and what the fourth would have been

1. **Disable the autorun value `HKCU\...\Run\Tavistock9`** on the host, after
   exporting the key for evidence. It stops the implant from coming back at next
   logon. It costs the business nothing tonight; the user's session is unaffected.
   It costs me the ability to see whether the adversary re-establishes persistence
   by the same mechanism, so I lose one signal about their playbook.
2. **Block `cdn-halcyon-sync.example` and `198.51.100.47:443` at the egress
   gateway, organisation-wide.** It stops this implant and any sibling copy of it
   from calling home. It costs the business nothing, since nothing legitimate
   resolves there. It costs me the beacon: once blocked, the implant's failures
   tell me less than its successes did.
3. **Isolate `PORTWAY-WS-114` at the switch, retaining remote management access.**
   It stops lateral movement off a host that has had an interactive intrusion. It
   costs a dispatch workstation its work for the shift, and if this is the only
   station on that shift, that is a business cost, not an IT one. It costs me
   live telemetry from the host, which is the real reason I would rather do it
   last and deliberately than first and reflexively.

The fourth action, with a fourth slot, would be a **memory capture and live
response collection from `iblenor.exe` before anything else** rather than
re-imaging. It lost because it is slow, it needs a tool nobody has deployed on
this estate yet, and the artefacts I need are already in the telemetry: hashes on
EID 11, the ProcessGuid chain on EID 1, the destination on EID 3. Collection would
add what the implant holds in memory, which matters for attribution and for
finding other hosts, not for stopping this one.

## Cut now, or watch a while

I would watch, for a bounded window: one shift, ending with a decision, not
drifting into a week.

The argument for cutting now is honest. The beacon is live, the implant is
persistent, and every hour it runs is an hour the adversary can use the host. If
they were to move laterally tonight, the cost lands on the client and the
explanation lands on us.

The argument for watching is what I would lose. Cutting the beacon ends the
exposure and ends my view at the same moment: I stop seeing what the implant
tries next, whether it fetches a second stage, and which other hosts it talks to.
That last one matters more than anything else in this note. I have one host, a
payload, and an endpoint whose name I recognise from another client. The question
Dana will be asked tomorrow is not "was this host compromised", it is "how far did
they get". Watching answers that, and blocking the destination while leaving the
persistence in place lets me watch without letting them work: the implant keeps
trying, fails, and the failures are evidence.

So: block the C2 now, leave the host running and monitored, disable autorun only
if I see a second-stage fetch attempt or any lateral traffic off the host, and
revisit at shift change with the decision already made. If nothing happens in that
window, isolate and re-image with the artefacts in hand. If something does, I have
the answer to the question that actually matters and a host that is already
contained at the network layer.
