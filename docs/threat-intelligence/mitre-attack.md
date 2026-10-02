# MITRE ATT&CK Framework

A knowledge base of adversary tactics (the goal) and techniques (how it is achieved), built from real-world observations.

## Why It Matters

ATT&CK gives defenders a shared vocabulary for attacker behavior. It is how I map what I see in an incident to what usually comes next, how I check which techniques my detections cover, and how hunts and playbooks stay focused on behavior attackers actually use.

## Reference

### Tactics

| ID | Tactic | Attacker Goal |
| :--- | :--- | :--- |
| TA0043 | Reconnaissance | Gather information to plan the attack |
| TA0042 | Resource Development | Set up infrastructure, accounts, and tools |
| TA0001 | Initial Access | Get into the network |
| TA0002 | Execution | Run malicious code |
| TA0003 | Persistence | Keep access across restarts and credential changes |
| TA0004 | Privilege Escalation | Gain higher permissions |
| TA0005 | Defense Evasion | Avoid detection |
| TA0006 | Credential Access | Steal account names and passwords |
| TA0007 | Discovery | Learn the environment |
| TA0008 | Lateral Movement | Move through the environment |
| TA0009 | Collection | Gather data of interest |
| TA0011 | Command and Control | Communicate with compromised systems |
| TA0010 | Exfiltration | Steal data |
| TA0040 | Impact | Disrupt, destroy, or manipulate systems and data |

Techniques are added and revised in each ATT&CK release. The tables below cover common techniques, not the full matrix.

### Initial Access

| Technique | Notes |
| :--- | :--- |
| [T1566 Phishing](https://attack.mitre.org/techniques/T1566/) | Still the most common entry point; see the [Phishing](../playbooks/incident-response/phishing.md) playbook |
| [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | VPNs, firewalls, and web applications; see [Exploited Edge Device](../playbooks/incident-response/edge-device-exploitation.md) |
| [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133/) | VPN, RDP, and Citrix with valid or stolen credentials |
| [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Credentials from phishing, reuse, or purchase |
| [T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189/) | Malicious or compromised websites |
| [T1195 Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/) | Compromised software or updates |
| [T1199 Trusted Relationship](https://attack.mitre.org/techniques/T1199/) | Access through an IT provider or partner |
| [T1091 Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/) | USB drives |
| [T1200 Hardware Additions](https://attack.mitre.org/techniques/T1200/) | Rogue devices plugged into the network |
| [T1659 Content Injection](https://attack.mitre.org/techniques/T1659/) | Malicious content injected into network traffic |

### Execution

| Technique | Notes |
| :--- | :--- |
| [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | PowerShell, cmd, bash, Python; see the [Suspicious PowerShell](../playbooks/alert-triage/suspicious-powershell.md) runbook |
| [T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/) | Running commands locally and on remote hosts |
| [T1204 User Execution](https://attack.mitre.org/techniques/T1204/) | A user opens a malicious file or link |

### Persistence

| Technique | Notes |
| :--- | :--- |
| [T1547 Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/) | Run keys, Startup folder |
| [T1053 Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/) | See the [Persistence](../playbooks/threat-hunting/persistence.md) hunt |
| [T1136 Create Account](https://attack.mitre.org/techniques/T1136/) | New local, domain, or cloud accounts |
| [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133/) | SSH, VPN, RDP gateways |

### Privilege Escalation

| Technique | Notes |
| :--- | :--- |
| [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Credentials for privileged accounts obtained through phishing or dumping |
| [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) | Unpatched local vulnerabilities |

### Defense Evasion

| Technique | Notes |
| :--- | :--- |
| [T1562 Impair Defenses](https://attack.mitre.org/techniques/T1562/) | Disabling or modifying security tools, Windows event logging, firewalls, and command history logging (for example `HISTCONTROL` on Linux) |
| [T1070 Indicator Removal](https://attack.mitre.org/techniques/T1070/) | Clearing Windows event logs (Event ID 1102), clearing Linux logs and command history, deleting files, timestomping |

### Credential Access

| Technique | What to Look For | Mitigation |
| :--- | :--- | :--- |
| [T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003/) | Process access to `lsass.exe` (Sysmon Event ID 10); reads of `/etc/shadow` (auditd) | Credential Guard, LSA protection, Protected Users, removing local admin rights |
| [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | Failed logons across many accounts or one account; see the [Password Spray](../playbooks/alert-triage/password-spray.md) runbook | MFA, lockout and smart lockout, strong passwords |
| [T1558.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) | RC4 service tickets (4769, `0x17`); see the [Kerberoasting](../playbooks/threat-hunting/kerberoasting.md) hunt | gMSAs, long service account passwords, AES-only Kerberos |

Offline cracking of stolen hashes uses tools like [Hashcat](https://hashcat.net/hashcat/) and [John the Ripper](../endpoint-forensics/tools/john-the-ripper.md).

### Discovery

| Technique | Common Commands | Notes |
| :--- | :--- | :--- |
| [T1087 Account Discovery](https://attack.mitre.org/techniques/T1087/) | `net user`, `net localgroup`, `net user /domain`, `net group "Domain Users" /domain` (Windows); `id`, `groups`, `cat /etc/passwd` (Linux); `dscacheutil -q group` (macOS); `ldapsearch` | Disabling "Enumerate administrator accounts on elevation" by Group Policy stops UAC prompts from listing admin accounts |
| [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | Port scanners, `nmap` | Internal scanning from a workstation is unusual |
| [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) | `dir`, `tree`, `find`, `locate` | Heavy use in a short time can indicate staging |

### Lateral Movement

| Technique | Notes |
| :--- | :--- |
| [T1021 Remote Services](https://attack.mitre.org/techniques/T1021/) | RDP, SMB/admin shares, DCOM, SSH, VNC, WinRM. Mitigate with MFA and limits on which hosts can reach these services; watch for logons from unusual source hosts |
| [T1534 Internal Spearphishing](https://attack.mitre.org/techniques/T1534/) | Phishing sent from a compromised internal mailbox; scan internal mail, not just inbound |

### Collection

| Technique | Notes |
| :--- | :--- |
| [T1114 Email Collection](https://attack.mitre.org/techniques/T1114/) | Mailbox access and forwarding rules; see the [New Inbox Forwarding Rule](../playbooks/alert-triage/inbox-forwarding-rule.md) runbook |
| [T1005 Data from Local System](https://attack.mitre.org/techniques/T1005/) | Archive creation and staging before exfiltration |
| [T1113 Screen Capture](https://attack.mitre.org/techniques/T1113/) | Unusual processes calling screenshot APIs |
| [T1123 Audio Capture](https://attack.mitre.org/techniques/T1123/) | Unusual processes accessing microphones |

### Command and Control

| Technique | Notes |
| :--- | :--- |
| [T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) | C2 over HTTP, HTTPS, and DNS. Cobalt Strike is a commercial adversary simulation tool that is widely abused for C2. See the [C2 Beaconing](../playbooks/threat-hunting/c2-beaconing.md) hunt |
| [T1102 Web Service](https://attack.mitre.org/techniques/T1102/) | Legitimate cloud services used for C2 |
| [T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571/) | Restrict outbound ports at the firewall and proxy |

### Exfiltration

| Technique | Notes |
| :--- | :--- |
| [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Unusual outbound data volumes |
| [T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) | Cloud storage uploads, tools like rclone |
| [T1029 Scheduled Transfer](https://attack.mitre.org/techniques/T1029/) | Outbound transfers at regular intervals |

### Impact

| Technique | What to Look For | Mitigation |
| :--- | :--- | :--- |
| [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) | Mass file renames and modifications; see the [Ransomware](../playbooks/incident-response/ransomware.md) playbook | Offline or immutable backups |
| [T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) | `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set recoveryenabled no` | Protected backups, alerting on these commands |
| [T1531 Account Access Removal](https://attack.mitre.org/techniques/T1531/) | Account management events 4723, 4724, 4725, 4726, 4740 | Baselines and alerting on bulk changes |
| [T1491 Defacement](https://attack.mitre.org/techniques/T1491/) | Unexpected changes to web content | Backups, WAF, protection against SQL injection and XSS |

## How I Use It

During an incident, I map each confirmed attacker action to a technique and look at the tactics around it: if I find credential dumping, I go looking for lateral movement and persistence next. Outside of incidents, I use [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layers to compare what my detections cover against the techniques most relevant to the environment, and that comparison decides which hunts and detections come next.

## Related

* [Playbooks](../playbooks/index.md), each mapped to the techniques they cover
* [Threat Hunting](../playbooks/threat-hunting/index.md)

## Resources

* [ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
* [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
* [MITRE D3FEND](https://d3fend.mitre.org/), a matching knowledge base of defensive techniques
