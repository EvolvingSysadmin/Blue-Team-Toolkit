# Persistence: Scheduled Tasks, Services, and Run Keys

## Hypothesis

An attacker who got code running on a host has set it to survive reboots with a scheduled task, a new service, or a registry Run key, and the persistence blends in well enough that no alert fired.

## ATT&CK

* [T1053.005 Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
* [T1543.003 Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
* [T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

## Data

* EDR: `DeviceEvents`, `DeviceRegistryEvents`, `DeviceProcessEvents`
* Windows Security 4698 (scheduled task created) and 4697 (service installed); System 7045 (service installed)

## Approach

Persistence is common and mostly legitimate, so I hunt by rarity: entries that exist on only a handful of hosts and point to user-writable locations.

New scheduled tasks and services, with how many hosts each appears on:

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("ScheduledTaskCreated", "ServiceInstalled")
| extend Fields = parse_json(AdditionalFields)
| extend Name = coalesce(tostring(Fields.TaskName), tostring(Fields.ServiceName))
| summarize Hosts = dcount(DeviceName), HostList = make_set(DeviceName, 10), FirstSeen = min(Timestamp) by ActionType, Name
| where Hosts <= 3
| order by FirstSeen desc
```

Scheduled tasks created from the command line:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

Run keys pointing to user-writable or unusual paths:

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
| where RegistryValueData has_any (@"\AppData\", @"\Temp\", @"\Users\Public\", @"\ProgramData\", "powershell", "mshta", "rundll32", "regsvr32")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

## What Normal Looks Like

* Tasks and services from software updaters (browsers, Office, PDF readers, drivers) appear on many hosts with consistent names
* IT deployment tools create tasks with known names and accounts
* I build an allowlist of these over time so the next hunt is quicker

Suspicious signs are: one or two hosts, random or misspelled names that imitate Microsoft tasks, actions that run PowerShell, `cmd /c`, `mshta`, or `rundll32`, and binaries in `AppData`, `Temp`, `ProgramData`, or `Users\Public`.

## If I Find Something

I check the binary or script the entry runs, then move to the [Endpoint Malware](../incident-response/endpoint-malware.md) playbook. The persistence mechanism becomes a detection.
