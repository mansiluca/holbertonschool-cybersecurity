Investigation note, PORTWAY-WS-114, case 13x01.

WHAT HAPPENED

1. Entry, 2026-09-18 07:55:00. explorer.exe (pid 17140, PORTWAY\sdumont) spawned wscript.exe (pid 19308, ProcessGuid {bd691e28-1800-4e04-8f79-9ee12aeb3956}) running C:\Users\sdumont\Downloads\PORTWAY-DISPATCH-UPDATE.js. The lure was named like a dispatch software update, which is what a dispatch workstation is expected to install.
2. Execution, 07:55:03.212. That script host spawned powershell.exe (pid 19312, ProcessGuid {a0e0be61-dffb-40af-9c7b-f0a6c40d4ea5}) with -nop -w hidden -enc: no profile, no window, an encoded payload.
3. Persistence, 07:55 and 07:55:14.051. The same interpreter wrote C:\Users\sdumont\AppData\Roaming\iblenor.exe (EID 11) and registered it for autorun as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Tavistock9 (EID 13).
4. Callback, 16:15:33.738. iblenor.exe (pid 19332, ProcessGuid {ec443170-b1e2-483e-9b49-c60d87f37252}) opened an outbound connection to 198.51.100.47 tcp/443, resolving as cdn-halcyon-sync.example.

The artefacts, by identifier: agent 001 on PORTWAY-WS-114, the lure PORTWAY-DISPATCH-UPDATE.js in Downloads, the payload C:\Users\sdumont\AppData\Roaming\iblenor.exe with the hash recorded on its EID 11, the run value Tavistock9, the C2 198.51.100.47 / cdn-halcyon-sync.example:443, and the ProcessGuids {bd691e28-...}, {a0e0be61-...} and {ec443170-...}. Process names and the powershell.exe hash 121E1253E10DBE8D2D06AAE33EDBC859 are shared with legitimate activity and identify nothing on their own.

THE NODE I HAD TO WORK FOR

pkg_7714, pid 19348, ProcessGuid {49fb0168-6c51-42f0-96fe-e45280d8b907}, running as PORTWAY\svc_nmdeploy with a package log at C:\ProgramData\Northmoor\logs\pkg_7714.log. Its lineage fits a malicious loader and a legitimate installer equally well, so the tree could not settle it.

Before looking, I wrote down what would settle it in each direction. Malicious: an EID 3 to 198.51.100.47, because a deployment package has no reason to reach the attacker endpoint. Benign: EID 3 only to internal hosts on 10.42.8.0/24 as the genuine package pkg_7708 does, plus a validating Northmoor manifest. My confidence was no better than 60/40 against.

What settled it was EID 3 by that ProcessGuid to 198.51.100.47, tcp/443, at 13:00:01. Verdict malicious, confidence high. My malicious prediction was the one that landed. The benign prediction was not foolish, it simply did not happen, and the difference between the two packages is that single connection.

WHAT I CLEARED

Portway's IT runs nmdeploy-agent.exe from C:\Program Files\Northmoor\DeployAgent\ as svc_nmdeploy at High integrity, spawning powershell.exe (pid 19292, ProcessGuid {5891c7e0-8bcc-40fb-96c2-d692884504ac}) with an encoded command and the signed stage script pkg_7708.ps1.

It is benign on two grounds somebody else can test. Provenance: the parent is a signed service binary under Program Files launched by the deploy service, not a user's double-click on a file in Downloads. Network: every EID 3 under {5891c7e0-...} goes to 10.42.8.0/24 (10.42.8.2, 10.42.8.10, 10.42.8.20, 10.42.8.30) and never to 198.51.100.47. It also writes no Run key, because a deployment tool does not need to survive a reboot on its own. Pull the ProcessGuid, check the EID 1 parent and every EID 3 destination: if either test fails, the clearance fails.

CONTAINMENT, THREE SELECTED ACTIONS AND ONE REJECTED

ACTION 1 (selected, slot 1 of 3). Disable the autorun value HKCU\...\Run\Tavistock9, after exporting the key for evidence. It stops iblenor.exe returning at the next logon. The business impact is none tonight, the user's session and the dispatch software are untouched. The visibility cost is that I lose the signal of whether the adversary re-establishes persistence by the same primitive. It ranks first because it costs nothing, removes a mechanism I already have the artefact for, and does not tip them off.

ACTION 2 (selected, slot 2 of 3). Block cdn-halcyon-sync.example and 198.51.100.47:443 at the egress gateway, organisation-wide. It stops this implant and any sibling copy calling home. The business impact is none, nothing legitimate resolves there. The visibility cost is the beacon's successful check-ins. It ranks second because blocking still logs each attempt, so I keep the timing signal while removing their ability to work, and every other Portway workstation becomes a detector for the same infrastructure.

ACTION 3 (selected, slot 3 of 3). Isolate PORTWAY-WS-114 at the switch, keeping remote management access. It stops lateral movement off a host with an interactive intrusion. The business impact is a dispatch workstation's shift, which is a business cost and not an IT one if it is the only station on that shift. The visibility cost is live telemetry from the host. It ranks third because it is the only action with a real business cost, and that cost is only worth paying once a trigger fires. Doing it first would buy safety with the view I need.

NOT SELECTED, the fourth action if a fourth slot existed:  memory capture of iblenor.exe and live response collection instead of re-imaging. It ranked below the three above because it is slow, needs a tool nobody has deployed on this estate, and adds mostly attribution value: the hash is already on the EID 11, the chain is already in the EID 1, the destination is already in the EID 3. It improves the answer to who and how far, not the answer to what is running now.

CUT NOW OR WATCH

My call is to watch, bounded to one shift, with a decision at the end of it: cut the C2 at the network now, leave the host running and monitored, and hold isolation until shift change unless a trigger fires.

Cutting the beacon ends the exposure and ends the view at the same moment. I would stop seeing whether the implant fetches a second stage and which other hosts it reaches, and that second question is the one Dana will be asked tomorrow: not whether this host fell, but how far they got. A blocked destination plus live persistence gives me the attempts without giving them the capability.

Triggers that end the watching: a second-stage fetch attempt, any EID 3 from this host into another internal subnet, or a second workstation resolving cdn-halcyon-sync.example. Any of those and I isolate immediately, because at that point containment beats the view. If nothing fires, isolate and re-image at shift change with the artefacts already in hand.
