# Sysmon

Sysinternals service and driver that logs detailed process, network, file, and registry activity to the Windows event log.

## When I Use It

* Hosts without EDR, where Sysmon gives most of the process and network visibility an investigation needs for free
* Alongside EDR, when I want the same telemetry in the SIEM with my own retention
* In a lab, to see exactly what a sample does

## Installation

* Download from <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>
* Install with a configuration file, as administrator: `sysmon64.exe -accepteula -i sysmonconfig.xml`
* Update the configuration on a running install: `sysmon64.exe -c sysmonconfig.xml`
* Events are written to Applications and Services Logs > Microsoft > Windows > Sysmon > Operational

!!! tip "Start from a community configuration"
    Without a configuration file Sysmon logs very little, and with an unfiltered one it floods the log. The [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) and [sysmon-modular](https://github.com/olafhartong/sysmon-modular) configurations are good starting points to tune from.

## Common Tasks

### Key Event IDs

| ID | Event | Investigation Use |
| :--- | :--- | :--- |
| 1 | Process creation | Command lines, parent processes, and hashes |
| 3 | Network connection | Which process connected where |
| 7 | Image loaded | DLL loading and sideloading |
| 8 | CreateRemoteThread | Process injection |
| 10 | Process access | Access to `lsass.exe` (credential dumping) |
| 11 | File created | Dropped payloads |
| 12, 13, 14 | Registry events | Run keys and other persistence |
| 22 | DNS query | Which process looked up which domain |

### Query Sysmon Events with PowerShell

```powershell
# Process creation events in the last hour
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date).AddHours(-1)}

# Processes that accessed lsass.exe
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |
    Where-Object { $_.Message -match 'lsass.exe' }
```

## Reading the Output

* Event ID 1 includes the parent process and command line, which is usually enough to tell an admin script from a malicious one
* Event ID 10 against `lsass.exe` is normal for some security tools and Windows components; the source process is what matters
* Event ID 22 ties DNS lookups to processes, which firewall and DNS server logs cannot do

## Related

* [Windows Event Logs](windows-event-logs.md)
* [Suspicious PowerShell](../playbooks/alert-triage/suspicious-powershell.md) runbook
* [Persistence](../playbooks/threat-hunting/persistence.md) hunt

## Resources

* [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
* [sysmon-modular](https://github.com/olafhartong/sysmon-modular)
* [Install and use Sysmon for malware investigation](https://support.sophos.com/support/s/article/KB-000038882?language=en_US)
