# MITRE ATT&CK Framework

* [ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
* [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/): build layers to show detection coverage or map an incident
* Enterprise tactics, in order:
  * Reconnaissance (TA0043), Resource Development (TA0042), Initial Access (TA0001), Execution (TA0002), Persistence (TA0003), Privilege Escalation (TA0004), Defense Evasion (TA0005), Credential Access (TA0006), Discovery (TA0007), Lateral Movement (TA0008), Collection (TA0009), Command and Control (TA0011), Exfiltration (TA0010), Impact (TA0040)
* Techniques are added and revised in each ATT&CK release; check the matrix for the current list

## Initial Access

[TA0001](https://attack.mitre.org/tactics/TA0001/)

* [Content Injection](https://attack.mitre.org/techniques/T1659/)
* [Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
* [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
* [External Remote Services](https://attack.mitre.org/techniques/T1133/)
* [Hardware Additions](https://attack.mitre.org/techniques/T1200/)
* [Phishing](https://attack.mitre.org/techniques/T1566/)
* [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/)
* [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
* [Trusted Relationship](https://attack.mitre.org/techniques/T1199/)
* [Valid Accounts](https://attack.mitre.org/techniques/T1078/)

## Execution

[TA0002](https://attack.mitre.org/tactics/TA0002/)

* [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/): PowerShell, cmd, bash, Python, and similar
* [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/): Windows administration feature that adversaries use to run commands locally and on remote hosts
* [User Execution](https://attack.mitre.org/techniques/T1204/): a user opens a malicious file or link

## Persistence

[TA0003](https://attack.mitre.org/tactics/TA0003/)

* [Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/): Run keys, Startup folder, and similar
* [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
* [Create Account](https://attack.mitre.org/techniques/T1136/)
* [External Remote Services](https://attack.mitre.org/techniques/T1133/): for example SSH, VPN, RDP gateways

## Privilege Escalation

[TA0004](https://attack.mitre.org/tactics/TA0004/)

* [Valid Accounts](https://attack.mitre.org/techniques/T1078/): using credentials obtained through phishing or dumping
* [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)

## Defense Evasion

[TA0005](https://attack.mitre.org/tactics/TA0005/)

* Ways adversaries evade or disable security defenses such as antivirus, EDR, logging, and human analysts
* [Impair Defenses](https://attack.mitre.org/techniques/T1562/): disrupting security tools
  * Disable or Modify Tools
  * Disable Windows Event Logging
  * Impair Command History Logging, for example setting `HISTCONTROL` so commands are not written to `~/.bash_history`
  * Disable or Modify System Firewall
  * Indicator Blocking
  * Disable or Modify Cloud Firewall
* [Indicator Removal](https://attack.mitre.org/techniques/T1070/)
  * Clear Windows Event Logs (Security log cleared: Event ID 1102)
  * Clear Linux or Mac System Logs
  * Clear Command History
  * File Deletion
  * Timestomp

## Credential Access

[TA0006](https://attack.mitre.org/tactics/TA0006/)

* [OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
  * LSASS Memory: credentials stored in memory, for example dumped with Mimikatz
    * Detect: monitor process access to `lsass.exe` (Sysmon Event ID 10)
  * `/etc/passwd` and `/etc/shadow`: copied for offline cracking; `/etc/shadow` is readable only by root
    * Detect: auditd rules on reads of `/etc/shadow`
* [Brute Force](https://attack.mitre.org/techniques/T1110/)
  * Includes password guessing, password spraying, credential stuffing, and offline cracking of hashes with tools like [Hashcat](https://hashcat.net/hashcat/)
  * Mitigations: account lockout policies, strong passwords, MFA, monitoring for failed logons

## Discovery

[TA0007](https://attack.mitre.org/tactics/TA0007/)

* [Account Discovery](https://attack.mitre.org/techniques/T1087/)
  * Local accounts: `net user` and `net localgroup` (Windows), `id` and `groups` (Linux and macOS), `cat /etc/passwd` (Linux)
  * Domain accounts: `net user /domain` and `net group "Domain Users" /domain` (Windows), `dscacheutil -q group` (macOS), `ldapsearch` (Linux)
  * Email and cloud accounts
  * Mitigation: disable the "Enumerate administrator accounts on elevation" setting with Group Policy so UAC prompts do not list administrator accounts
* [Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
* [File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)

## Lateral Movement

[TA0008](https://attack.mitre.org/tactics/TA0008/)

* [Remote Services](https://attack.mitre.org/techniques/T1021/)
  * Remote Desktop Protocol (RDP)
  * SMB/Windows Admin Shares
  * Distributed Component Object Model (DCOM)
  * SSH
  * VNC
  * Windows Remote Management (WinRM)
  * Mitigations: MFA, restrict which hosts can reach these services, monitor logon activity for unusual source hosts
* [Internal Spearphishing](https://attack.mitre.org/techniques/T1534/): sending phishing email from a compromised internal mailbox
  * Mitigation: scan internal email and attachments, not just inbound

## Collection

[TA0009](https://attack.mitre.org/tactics/TA0009/)

* [Email Collection](https://attack.mitre.org/techniques/T1114/)
* [Audio Capture](https://attack.mitre.org/techniques/T1123/)
* [Screen Capture](https://attack.mitre.org/techniques/T1113/)
* [Data from Local System](https://attack.mitre.org/techniques/T1005/)
* Mitigations and detection: audit mailbox access and forwarding rules, MFA, monitor unusual processes accessing microphones or taking screenshots, monitor for heavy use of `dir`, `find`, `tree`, and `locate` and for staging of archives

## Command and Control

[TA0011](https://attack.mitre.org/tactics/TA0011/)

* [Application Layer Protocol](https://attack.mitre.org/techniques/T1071/): C2 over HTTP, HTTPS, DNS
  * Cobalt Strike is a commercial adversary simulation tool that is widely abused for C2
  * Detect: NIDS/NIPS, beaconing analysis on proxy and firewall logs
* [Web Service](https://attack.mitre.org/techniques/T1102/): legitimate cloud services used for C2
* [Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
  * Mitigation: restrict outbound ports at the firewall and proxy, inspect traffic

## Exfiltration

[TA0010](https://attack.mitre.org/tactics/TA0010/)

* [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
  * Detect: unusual outbound data volumes, frequency analysis
* [Scheduled Transfer](https://attack.mitre.org/techniques/T1029/)
  * Detect: outbound transfers at regular intervals, NIDS

## Impact

[TA0040](https://attack.mitre.org/tactics/TA0040/)

* [Account Access Removal](https://attack.mitre.org/techniques/T1531/): deleting or locking accounts, changing passwords
  * Detect: Windows account management events (4723, 4724, 4725, 4726, 4740), comparison against baselines
* [Defacement](https://attack.mitre.org/techniques/T1491/): changing content to deliver a message, intimidate, or claim credit
  * Mitigation: restore from backup, WAF, defend against SQL injection and cross-site scripting
* [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/): ransomware
  * Mitigation: offline or immutable backups
* [Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/): deleting shadow copies and backups before encryption
  * Detect: command lines using `vssadmin delete shadows`, `wbadmin delete catalog`, and `bcdedit /set recoveryenabled no`
