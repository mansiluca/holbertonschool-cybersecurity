# 13x01 Ground Truth — Task 6: the detection rule

## The rule

A Wazuh rule on the persistence action, not on the interpreter that performed it:

```xml
<group name="sysmon,persistence,portway_custom,">
  <rule id="100900" level="12">
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject">CurrentVersion\\Run</field>
    <field name="win.eventdata.details">AppData|\\Temp\\|\\Downloads\\|\\Users\\Public\\</field>
    <description>Autorun persistence pointing at a user-writable path: $(win.eventdata.details)</description>
    <mitre><id>T1547.001</id></mitre>
  </rule>
</group>
```

## The behaviour it keys on, and why it survives the tool being shared

It keys on the outcome of the activity: somebody arranged for a file in a
user-writable directory to be executed again at logon, by registering it in the
per-user or machine-wide Run key. That is the action, and an action is what a
detection should describe. It says nothing about PowerShell, so the fact that
the attacker and Portway's IT both drive this host through the same signed
interpreter is irrelevant to the rule.

The attacker's chain wrote an executable into `AppData\Roaming` and then pointed
`HKCU\...\CurrentVersion\Run\Tavistock9` at it. The deployment chain runs signed
packages from `C:\Program Files\Northmoor\` and never registers autorun, because
it does not need to: a deployment tool runs when it runs, it does not need to
survive a reboot by itself. The difference between the two chains is what they
did to the host, not the binary they used to do it.

## Result of running it against the legitimate activity on this host

Run over the whole telemetry window of agent 001 on `PORTWAY-WS-114`:

- one match: `HKCU\...\CurrentVersion\Run\Tavistock9` -> `C:\Users\sdumont\AppData\Roaming\iblenor.exe`, the intrusion;
- zero matches on the administrative chain (`svc_nmdeploy` -> `nmdeploy-agent.exe` -> `powershell.exe`), which writes no Run key at all.

It fires on the attack and stays silent on the administrator. That is the only
result that matters: a rule that fires on the admin is worse than no rule,
because the team learns to ignore it and then ignores it on the day it is right.

## First attempt, and what I changed

The first version keyed on the tool: `powershell.exe` with `-EncodedCommand`,
`-nop` and a hidden window. It caught the malicious PowerShell, and it also fired
on the Northmoor deployment agent, which legitimately runs
`powershell.exe -ExecutionPolicy Bypass -EncodedCommand` on every package it
installs. Two hits in the same window, one of them the IT department doing its
job. That version would have been muted within a week.

The change was to move the rule off the interpreter and onto the persistence
behaviour: a Run-key value pointing at a user-writable path. The deployment chain
never does that, so the final rule keeps the true positive and drops the false
positive without weakening the condition that caught the attack.
