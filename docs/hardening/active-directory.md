# Active Directory Hardening

Controls that make Active Directory harder to compromise and easier to monitor.

## Why It Matters

Active Directory controls access to almost everything in a Windows environment, so it is the main target in most serious intrusions and ransomware attacks. An attacker with Domain Admin can reach every system; most of these controls exist to stop that from happening, or to make it loud when it does.

## Reference

### Privileged Access

| Control | Purpose |
| :--- | :--- |
| Separate admin accounts | Admin credentials are not exposed through email and web browsing |
| Minimal membership in Domain Admins, Enterprise Admins, Schema Admins, and Administrators | Fewer accounts that can compromise the whole domain |
| Tiered administration | Domain Admin credentials are only used on Domain Controllers and other Tier 0 systems, so they are never cached on workstations |
| Privileged Access Workstations (PAWs) | Dedicated, hardened machines for Tier 0 administration |
| Protected Users group | Blocks NTLM, delegation, and weak Kerberos encryption for privileged accounts |
| Windows LAPS | A unique, rotated local administrator password on every machine, which stops lateral movement with one shared password |
| MFA for remote and privileged access | Stolen passwords alone are not enough |

### Authentication

| Control | Purpose |
| :--- | :--- |
| Disable LM and NTLMv1; audit and reduce NTLM | Removes weak protocols used in relay and cracking attacks |
| Require SMB signing; disable SMBv1 | Prevents SMB relay attacks |
| Require LDAP signing and channel binding | Prevents LDAP relay attacks |
| Disable LLMNR and NetBIOS over TCP/IP | Prevents name poisoning attacks that capture credentials |
| Group Managed Service Accounts (gMSAs) and long, random service account passwords | Defeats Kerberoasting |
| AES-only Kerberos; disable RC4 | Makes Kerberoasting much harder |
| No accounts with "Do not require Kerberos preauthentication" | Prevents AS-REP roasting |
| No unconstrained delegation outside Domain Controllers | Stops ticket theft through delegation |
| Periodic `krbtgt` password reset (twice, with replication between) | Limits the lifetime of forged Kerberos tickets |

### Domain Controllers and Services

| Control | Purpose |
| :--- | :--- |
| Patch Domain Controllers promptly | Many AD attacks rely on known vulnerabilities |
| No other roles or software on Domain Controllers | Smaller attack surface on Tier 0 |
| Disable the Print Spooler on Domain Controllers | Removes a common coercion and exploitation path |
| Review AD Certificate Services templates (ESC1 and later) | Misconfigured templates allow privilege escalation |
| Limit internet exposure of AD-integrated services | Fewer entry points |
| Network Access Control (NAC) | Keeps unknown devices off the network |

### Monitoring and Assessment

| Control | Purpose |
| :--- | :--- |
| Advanced Audit Policy on Domain Controllers, forwarded to the SIEM | The events in [Windows Event Logs](../siem-and-log-analysis/windows-event-logs.md) exist and are kept |
| Alerts on privileged group changes (4728, 4732, 4756), new accounts (4720), and RC4 service tickets (4769) | Catches the common steps toward domain compromise |
| Regular assessments with PingCastle, Purple Knight, or BloodHound | Finds misconfigurations and attack paths before attackers do |
| Penetration testing | Validates that the controls work |
| User awareness training | Fewer phished credentials to start with |

!!! warning "Test before enforcing"
    Many of these controls (disabling NTLM, requiring signing, removing RC4) can break older applications and devices. Audit first, fix what would break, then enforce.

## How I Use It

I start with an assessment tool like PingCastle to get a prioritized list, because it shows the real attack paths in the environment rather than a generic checklist. Privileged account hygiene comes first (fewer Domain Admins, separate admin accounts, LAPS), then the authentication changes, each one audited before it is enforced. The monitoring rows are what tell me whether the rest is holding.

## Related

* [Active Directory Privileged Compromise](../playbooks/incident-response/ad-privileged-compromise.md) playbook
* [New Privileged Account](../playbooks/alert-triage/new-privileged-account.md) runbook
* [Kerberoasting](../playbooks/threat-hunting/kerberoasting.md) hunt

## Resources

* [Microsoft: Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Microsoft: Enterprise access model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
* [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
* [PingCastle](https://www.pingcastle.com/)
* [BloodHound](https://github.com/SpecterOps/BloodHound)
