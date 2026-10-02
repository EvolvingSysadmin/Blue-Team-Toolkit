# Active Directory Hardening

## Privileged Access

* Use separate administrator accounts; do not use them for email or web browsing
* Keep membership of Domain Admins, Enterprise Admins, Schema Admins, and built-in Administrators to a minimum and review it regularly
* Use a tiered administration model so Domain Admin credentials are only used on Domain Controllers and Tier 0 systems
* Use Privileged Access Workstations (PAWs) for administering Tier 0
* Add privileged accounts to the Protected Users group
* Deploy Windows LAPS so every machine has a unique, rotated local administrator password
* Require MFA for remote access and privileged access

## Authentication

* Disable LM and NTLMv1; audit and reduce NTLM use
* Require SMB signing on all systems and disable SMBv1
* Require LDAP signing and LDAP channel binding on Domain Controllers
* Disable LLMNR and NetBIOS over TCP/IP to prevent name poisoning attacks
* Kerberoasting defenses
  * Use Group Managed Service Accounts (gMSAs) where possible
  * Give other service accounts long, random passwords
  * Allow only AES encryption for Kerberos and disable RC4
* AS-REP roasting defense: no accounts with "Do not require Kerberos preauthentication" set
* Remove unconstrained delegation from everything except Domain Controllers
* Reset the `krbtgt` account password periodically (twice, with replication between resets) and after any suspected compromise

## Domain Controllers and Services

* Patch Domain Controllers promptly
* Do not install other roles or software on Domain Controllers
* Disable the Print Spooler service on Domain Controllers
* Review Active Directory Certificate Services (AD CS) templates for misconfigurations that allow privilege escalation (ESC1 through ESC8 and later)
* Limit exposure of AD services and applications to the internet
* Enforce Network Access Control (NAC)

## Monitoring and Assessment

* Enable Advanced Audit Policy on Domain Controllers and forward logs to the SIEM; see [Windows Event Logs](../siem-and-log-analysis/windows-event-logs.md)
* Alert on changes to privileged groups (4728, 4732, 4756), new accounts (4720), and Kerberos anomalies (4769 with RC4)
* Run regular AD security assessments with tools such as PingCastle, Purple Knight, and BloodHound
* Perform penetration tests and vulnerability assessments to validate controls
* Train users to recognize phishing and report suspicious activity

## Resources

* [Microsoft: Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Microsoft: Enterprise access model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
* [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
* [PingCastle](https://www.pingcastle.com/)
* [BloodHound](https://github.com/SpecterOps/BloodHound)
