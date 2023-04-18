# MITRE ATT&CK Framework

* MITRE ATT&CK Framework Stages: <https://attack.mitre.org/matrices/enterprise/>
  * MITRE ATT&CK Navigator: <https://mitre-attack.github.io/attack-navigator/>
* Initial access 9 techniques:
  * [Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
  * [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
  * [External Remote Services](https://attack.mitre.org/techniques/T1133/)
  * [Hardware Additions](https://attack.mitre.org/techniques/T1200/)
  * [Phishing](https://attack.mitre.org/techniques/T1566/)
  * [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/)
  * [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
  * [Trusted Relationship](https://attack.mitre.org/techniques/T1199/)
  * [Valid Accounts](https://attack.mitre.org/techniques/T1078/)
* Execution technique examples: <https://attack.mitre.org/tactics/TA0002/>
  * [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
  * Administrative feature of windows, WMI service used for local and remote access to SMB and the Remote Procedure Call Service (RPCS), MITRE provides specific identification of WMI
  * [User Execution](https://attack.mitre.org/techniques/T1204/)
* Persistence examples: <https://attack.mitre.org/tactics/TA0003/>
  * [Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
  * [External Remote Services](https://attack.mitre.org/techniques/T1133/)
    * EG SSH, FTP, VPN
* Privilege escalation examples: <https://attack.mitre.org/tactics/TA0004/>
  * [Valid Accounts](https://attack.mitre.org/techniques/T1078/)
    * Obtaining valid accounts (eg via phishing)
  * [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
* Defense evasion: <https://attack.mitre.org/tactics/TA0005/>
  * Ways that adversaries will work to evade or disable security defenses such as antivirus, endpoint detection and response, logging, and human analysts
  * Impair defenses: disrupting operation of security tools (eg SIEM)
    * Disable of Modify Tools
    * Disable Windows Event Logging
    * HISTCONTROL (used to not log command history) which affects `~/.bash_history`
    * Disable or Modify System Firewall
    * Indicator Blocking
    * Disable or Modify Cloud Firewall
  * Indicator removal:
    * Deleting bash history
    * Deleting files
    * Deleting raw log files
    * Timestomping
* Credential access: <https://attack.mitre.org/tactics/TA0006/>
  * [OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
    * LSASS Memory: credentials stored in memory, eg using Mimikatz
    * Monitor lsass.exe in Windows
    * Use AuditD for Linux
    * /etc/passwd /etc/shadow: dumping /etc/passwd and /etc/shadow (only accessible by root) files for password cracking
  * [Brute Force](https://attack.mitre.org/techniques/T1110/)
    * Hashcat can be used to attack encrupted passwords using brute force: <https://hashcat.net/hashcat/>
    * Mitigations: account lockout policies, better passwords, MFA, log monitoring
* Discovery: <https://attack.mitre.org/tactics/TA0007/>
  * Account discovery:
    * Local accounts: `net user` and `net localgroup` (windows), `id` and `groups` (MacOS), `/etc/passwd` using `cat`, `string` or `head` (Linux)
    * Domain accounts: `net user /domain` and `net group domain` (windows), `dscacheutil -q group` (MacOS), `ldapsearch` (linux)
    * Email and cloud accounts
    * Mitigations: disable the registry key to prevent administrator accounts from being enumerated, group policy can force this change network-wide
  * Network service discovery
  * File and directory discovery
  * Lateral movement: <https://attack.mitre.org/tactics/TA0008/>
    * Enumerating internal remote services, eg:
      * Remote Desktop Protocol (RDP)
      * SMB/Windows Admin Shares
      * Distributed Component Object Model
      * SSH
      * VNC
      * Windows Remote Management (WINRM)
      * Mitigating enumeration: use MFA, monitor timelines of logon activity
    * Internal spearphishing, eg using a script to email other users from a compromised systems emali client
      * Scan eamil/attachments for mitigation
* Collection: <https://attack.mitre.org/tactics/TA0009/>
  * Email collection
  * Audio capture
  * Screen capture
  * Data from local system
  * Mitigations: audit, encryption, MFA, monitor api calls releated to system audio, monitor unusual processes that access microphones, API calls taking screenshots
  * Data from local system mitigation: monitor for commands such as dir, find, tree, locate; monitor for excessive usage of commands in CMD and powershell related to exfiltration
* Command and control: <https://attack.mitre.org/tactics/TA0011/>
  * Application layer using protocols like http, https, dns
  * Cobalt strike is an example of a C2 application  
    * Mitigation: NIDS/NIPS, monitor network data flows
  * Web service: legit web services may be used for C2
  * Nonstandard ports: C2 typically uses ports that aren't associated with services
    * Mitigation: restrict proxies/firewall ports for outbound connections, packet inspection
* Exfiltration: <https://attack.mitre.org/tactics/TA0010/>
  * Exfil Over C2 Channel
    * Mitigation: frequency analysis
  * Scheduled transfer
    * Mitigation: NIPS/NIDS
* Impact: <https://attack.mitre.org/tactics/TA0040/>
  * EG disrupting availability and intergrity
    * Account access removal:
    * Deleting or locking accounts
    * Password changes
    * Mitigation: windows log monitoring, baseline comparison
    * Defacement:
    * Delivering messaging,
    * Intimidation
    * Claiming credit for an intrusion
    * Mitigation: revert to latest backup, WAF to monitor websites, defend against SQL injection and cross site scripting
    * Data encryption (eg ransomware):
    * Mitigations: data backups, monitor specific command-line usages such as vssadmin, wbadmin, bcdedit
