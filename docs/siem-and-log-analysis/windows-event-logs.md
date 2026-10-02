# Windows Event Logs

* Description: Windows event IDs that help in log analysis. Most security events are in the Security log; events for domain accounts (Kerberos, domain account changes) are logged on Domain Controllers
* Windows Event Logs are binary files stored here:
  * Windows Vista / Server 2008 and later: `%SystemRoot%\System32\winevt\Logs\*.evtx`
  * Windows XP / Server 2003 and earlier: `%SystemRoot%\System32\config\*.evt`
* Many events only appear if the matching audit policy is enabled (Advanced Audit Policy Configuration)

## Event Log Categories

* Application: events logged by applications (execution, deployment errors, etc.)
* System: events logged by the operating system (device loading, startup errors, service changes, etc.)
* Security: events relevant to the security of the system (logons and logoffs, object access, privilege use, account changes)
* Directory Service: available only on Domain Controllers; Active Directory events
* DNS Server: available only on DNS servers
* File Replication Service / DFS Replication: available only on Domain Controllers; replication events
* Applications and Services Logs: per-component logs such as `Microsoft-Windows-PowerShell/Operational`, `Microsoft-Windows-Sysmon/Operational`, and `Microsoft-Windows-TerminalServices-*`

## Logon and Logoff (Security)

* 4624: successful logon
* 4625: failed logon
* 4634: logoff
* 4647: user initiated logoff
* 4648: logon attempted with explicit credentials (for example `runas`)
* 4672: special privileges assigned to new logon (an administrator-equivalent account logged on)
* 4649: replay attack detected
* Logon types (field in 4624/4625)
  * 2: interactive (console)
  * 3: network (SMB, mapped drives, many remote tools)
  * 4: batch (scheduled tasks)
  * 5: service
  * 7: unlock
  * 8: network cleartext
  * 9: new credentials (`runas /netonly`)
  * 10: remote interactive (RDP)
  * 11: cached interactive

## Kerberos and NTLM (Domain Controllers)

* 4768: Kerberos TGT requested
* 4769: Kerberos service ticket requested (high volumes of RC4 tickets can indicate Kerberoasting)
* 4771: Kerberos pre-authentication failed
* 4776: NTLM credential validation

## Account Changes (Security)

* 4720: user account created
* 4722: user account enabled
* 4725: user account disabled
* 4726: user account deleted
* 4738: user account changed
* 4740: user account locked out
* 4767: user account unlocked
* 4723: attempt to change own password
* 4724: attempt to reset another account's password
* 4728: member added to security-enabled global group
* 4732: member added to security-enabled local group
* 4756: member added to security-enabled universal group

## Object Access (Security, requires auditing)

* 4656: a handle to an object was requested
* 4658: the handle to an object was closed
* 4659: a handle to an object was requested with intent to delete
* 4660: an object was deleted
* 4663: an attempt was made to access an object (a high number of these with delete access can indicate mass deletion or ransomware)
* 4985: the state of a transaction has changed

## Process, Service, and Task Activity

* 4688 (Security): process created; enable command line auditing to capture the full command line
* 4697 (Security): service installed
* 7045 (System): new service installed
* 7036 (System): service entered the running or stopped state
* 7040 (System): service start type changed
* 4698 (Security): scheduled task created
* 4104 (`Microsoft-Windows-PowerShell/Operational`): PowerShell script block logging

## Policy and Log Changes

* 4704: user right assigned
* 4717: system security access granted to an account
* 4719: system audit policy changed
* 4739: domain policy changed
* 4706: new trust created to a domain
* 4675: SIDs were filtered
* 1102 (Security): audit log cleared
* 104 (System): System log cleared
* 1074 (System): shutdown or restart initiated by a process or user
* 6005 / 6006 (System): Event Log service started / stopped, a proxy for boot and shutdown

## Legacy Event IDs

* Windows XP / Server 2003 and earlier used three-digit IDs (for example 528 successful logon, 529 to 537 and 539 failed logons, 538 logoff, 624 account created)
* Most legacy Security IDs map to the current ID by adding 4096 (528 -> 4624, 529 -> 4625, 624 -> 4720)

## Resources

* [Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)
* [Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
* [Detecting a Security Threat in Event Logs](https://blog.netwrix.com/2014/12/03/detecting-a-security-threat-in-event-logs/)
* [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
* [Windows security auditing: Event Log FAQ](https://eventlogxp.com/essentials/securityauditing.html)
* [Windows Security Event Logs: my own cheatsheet](https://andreafortuna.org/2019/06/12/windows-security-event-logs-my-own-cheatsheet/)
* [Common Windows IDs for SOC](https://www.socinvestigation.com/most-common-windows-event-ids-to-hunt-mind-map/)
* [MyEventLog](https://www.myeventlog.com/)
* [Event ID databases](https://github.com/stuhli/awesome-event-ids#event-id-databases)
