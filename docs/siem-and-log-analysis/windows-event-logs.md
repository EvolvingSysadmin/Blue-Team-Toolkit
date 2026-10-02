# Windows Event Logs

Event IDs and log locations for investigating logons, account changes, process execution, and tampering on Windows systems.

## Why It Matters

Windows event logs are the main record of who logged on where, what accounts and groups changed, and what ran. They answer most of the early questions in an incident: which account, which host, when, and from where. They are also a target: clearing the Security log is one of the first things many attackers do, which is why forwarding them to a SIEM matters.

!!! warning "Audit policy decides what exists"
    Many of these events are only written if the matching audit policy is enabled. Check the effective policy with `auditpol /get /category:*` before concluding that something did not happen. Events for domain accounts (Kerberos, domain account changes) are logged on Domain Controllers, not on the workstation.

## Reference

### Log Files

| Windows Version | Location |
| :--- | :--- |
| Vista / Server 2008 and later | `%SystemRoot%\System32\winevt\Logs\*.evtx` |
| XP / Server 2003 and earlier | `%SystemRoot%\System32\config\*.evt` |

### Log Channels

| Log | Contents |
| :--- | :--- |
| Security | Logons, account and group changes, privilege use, object access, policy changes |
| System | Services, drivers, startup and shutdown, OS errors |
| Application | Events written by applications |
| Directory Service | Active Directory events (Domain Controllers only) |
| DNS Server | DNS server events (DNS servers only) |
| DFS Replication / File Replication Service | Domain Controller replication |
| Microsoft-Windows-PowerShell/Operational | PowerShell script block logging (4104) |
| Microsoft-Windows-Sysmon/Operational | [Sysmon](sysmon.md) events, if installed |
| Microsoft-Windows-TerminalServices-* | RDP session connections and logons |

### Logon and Logoff (Security)

| ID | Event | Notes |
| :--- | :--- | :--- |
| 4624 | Successful logon | Check the logon type, source IP, and workstation name |
| 4625 | Failed logon | The status and sub-status codes give the reason |
| 4634 | Logoff | Match to 4624 with the Logon ID to get session length |
| 4647 | User initiated logoff | |
| 4648 | Logon with explicit credentials | `runas`, and some lateral movement tools |
| 4672 | Special privileges assigned to new logon | An administrator-equivalent account logged on |
| 4649 | Replay attack detected | |

### Logon Types

| Type | Name | Typical Source |
| :--- | :--- | :--- |
| 2 | Interactive | Console logon |
| 3 | Network | SMB shares, mapped drives, many remote management tools |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service accounts starting services |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Credentials sent in cleartext, often IIS basic authentication |
| 9 | NewCredentials | `runas /netonly` |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Logon with cached domain credentials, no DC contact |

### Kerberos and NTLM (Domain Controllers)

| ID | Event | Notes |
| :--- | :--- | :--- |
| 4768 | Kerberos TGT requested | Logon to the domain |
| 4769 | Kerberos service ticket requested | Encryption type `0x17` (RC4) for user service accounts can indicate Kerberoasting |
| 4771 | Kerberos pre-authentication failed | Failed domain logon, often a bad password |
| 4776 | NTLM credential validation | |

### Account Management (Security)

| ID | Event |
| :--- | :--- |
| 4720 | User account created |
| 4722 | User account enabled |
| 4725 | User account disabled |
| 4726 | User account deleted |
| 4738 | User account changed |
| 4740 | User account locked out |
| 4767 | User account unlocked |
| 4723 | Attempt to change own password |
| 4724 | Attempt to reset another account's password |
| 4728 | Member added to security-enabled global group |
| 4732 | Member added to security-enabled local group |
| 4756 | Member added to security-enabled universal group |

### Object Access (Security, requires auditing)

| ID | Event |
| :--- | :--- |
| 4656 | A handle to an object was requested |
| 4658 | The handle to an object was closed |
| 4659 | A handle to an object was requested with intent to delete |
| 4660 | An object was deleted |
| 4663 | An attempt was made to access an object |
| 4985 | The state of a transaction has changed |

A spike in 4663 events with delete access can indicate mass deletion or ransomware.

### Process, Service, and Scheduled Task

| ID | Log | Event |
| :--- | :--- | :--- |
| 4688 | Security | Process created (enable command line auditing to record the command line) |
| 4697 | Security | Service installed |
| 7045 | System | New service installed |
| 7036 | System | Service entered the running or stopped state |
| 7040 | System | Service start type changed |
| 4698 | Security | Scheduled task created |
| 4104 | PowerShell/Operational | PowerShell script block logged |

### Policy Changes and Log Tampering

| ID | Log | Event |
| :--- | :--- | :--- |
| 4704 | Security | User right assigned |
| 4717 | Security | System security access granted to an account |
| 4719 | Security | System audit policy changed |
| 4739 | Security | Domain policy changed |
| 4706 | Security | New trust created to a domain |
| 4675 | Security | SIDs were filtered |
| 1102 | Security | Audit log cleared |
| 104 | System | System log cleared |
| 1074 | System | Shutdown or restart initiated by a process or user |
| 6005 / 6006 | System | Event Log service started / stopped (a proxy for boot and shutdown) |

### Legacy Event IDs

Windows XP and Server 2003 used three-digit Security event IDs. Most map to the current ID by adding 4096.

| Legacy | Current | Event |
| :--- | :--- | :--- |
| 528 | 4624 | Successful logon |
| 529 | 4625 | Failed logon |
| 538 | 4634 | Logoff |
| 624 | 4720 | User account created |

## How I Use It

I start from a question, not from the log. "Did this account log on to this server, and from where?" means 4624 on that server filtered to the account, then reading the logon type and source IP. Type 10 from an unexpected workstation reads very differently from type 3 from a file server.

From there I widen out: 4672 to see whether the session was privileged, 4688 or Sysmon for what ran during it, and the matching 4634 for when it ended. On Domain Controllers I use 4768, 4769, and 4776 to see where else the account authenticated.

On a live host or an exported .evtx file I query with PowerShell:

```powershell
# Failed logons in the last 24 hours
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)}

# Logons from an exported log file
Get-WinEvent -FilterHashtable @{Path='C:\cases\Security.evtx'; Id=4624} |
    Select-Object TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='LogonType';e={$_.Properties[8].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}

# Export a log for offline analysis
wevtutil epl Security C:\cases\Security.evtx
```

For large sets of exported logs, [DeepBlueCLI](deepbluecli.md) or a SIEM is faster than reading events one at a time.

## Related

* [Password Spray](../playbooks/alert-triage/password-spray.md) runbook
* [New Privileged Account](../playbooks/alert-triage/new-privileged-account.md) runbook
* [Active Directory Privileged Compromise](../playbooks/incident-response/ad-privileged-compromise.md) playbook
* [Kerberoasting](../playbooks/threat-hunting/kerberoasting.md) hunt
* [Sysmon](sysmon.md), [DeepBlueCLI](deepbluecli.md), [Windows Artifacts](../endpoint-forensics/windows-artifacts.md)

## Resources

* [Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)
* [Microsoft: Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
* [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
* [Common Windows Event IDs for SOC](https://www.socinvestigation.com/most-common-windows-event-ids-to-hunt-mind-map/)
* [Event ID databases](https://github.com/stuhli/awesome-event-ids#event-id-databases)
