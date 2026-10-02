# Preparation

The work done before an incident that decides how well the response goes: the plan, the people, the visibility, and the controls.

## Why It Matters

Most of what slows down an incident response is discovered during the incident: logs that were never collected, backups nobody has tested, no way to reach the people who can approve a shutdown, an asset inventory that is out of date. Preparation is the phase where those gaps are cheap to fix.

## Reference

### Incident Response Plan

| Element | What It Covers |
| :--- | :--- |
| Scope and definitions | What counts as an event versus an incident |
| Roles and responsibilities | Incident lead, technical responders, communications, legal, executive sponsor |
| Severity levels | Criteria and the response expected at each level |
| Escalation and contacts | Who is notified at each severity, with after-hours and out-of-band contact details |
| Decision authority | Who can approve taking systems offline, engaging outside firms, or contacting law enforcement |
| External parties | Cyber insurance carrier, outside counsel, IR retainer firm, vendors, law enforcement |
| Notification requirements | Regulatory, contractual, and breach notification obligations and their deadlines |
| Lifecycle procedures | How each phase is carried out, with links to playbooks |
| Review | How often the plan is tested and updated |

### Team and Playbooks

* Name an incident lead and backups; small teams need backups most
* Write [playbooks](../playbooks/incident-response/index.md) for the incidents most likely to happen
* Keep an out-of-band communication channel ready in case email and chat are compromised or down
* Agree on evidence handling ahead of time; see [Evidence Handling](../endpoint-forensics/evidence-handling.md)

### Visibility

| Source | What to Collect | Notes |
| :--- | :--- | :--- |
| Identity | Entra ID sign-in and audit logs, Domain Controller Security logs | Cloud sign-in logs have short default retention; export them to a SIEM |
| Endpoints | EDR telemetry, Windows Security, Sysmon, PowerShell logs | Enable command line and script block logging |
| Email | Mail flow, message trace, Microsoft 365 unified audit log | Confirm mailbox auditing is on |
| Network | Firewall, VPN, proxy, DNS | Edge device logs must leave the device; attackers clear local logs |
| Cloud | Cloud provider audit logs (for example CloudTrail, Azure Activity) | |

Retention needs to cover the time it takes to notice an intrusion, which is often weeks, not days.

### Asset Knowledge

* Asset inventory, including internet-facing systems
* Network diagrams and segmentation
* Critical systems and data, with their owners
* Privileged accounts and service accounts

### Defensive Controls

| Area | Controls |
| :--- | :--- |
| Network | Firewalls, segmentation, DMZ, NIDS/NIPS, web proxy, NAC |
| Endpoint | EDR, antivirus, host firewalls, application allowlisting, hardened baselines |
| Identity | MFA, Conditional Access, tiered admin accounts, LAPS |
| Email | SPF, DKIM, DMARC, external sender tagging, attachment filtering, sandboxing |
| Data | Backups including offline or immutable copies, encryption, DLP |
| Monitoring | Centralized logging and SIEM with alerting |
| People | Awareness training, phishing simulations, a simple way to report suspicious email |
| Physical | Access control for server rooms and network closets |

### Exercises

* **Tabletop exercises:** walk through a scenario such as ransomware or BEC with IT, leadership, and anyone with decision authority
* **Restore tests:** restore real systems from backup and time how long it takes
* **Technical drills:** isolate a test host with EDR, pull logs for a given user, purge an email from all mailboxes

!!! tip "Test the plan, not just the backups"
    A tabletop exercise usually finds problems no technical test would: an outdated contact list, nobody sure who can approve taking a system offline, or a playbook that assumes a tool you no longer have.

## How I Use It

I treat preparation as a list of questions I want answered before I need them. Can I see every sign-in for an account over the last 90 days? Can I isolate any endpoint in a minute? When did we last restore a server from backup, and how long did it take? Who do I call at the insurance carrier, and who can approve shutting down a production system at 2 a.m.?

Every question I cannot answer becomes a task. After every incident and every exercise, the answers go back into the plan and the playbooks.

## Related

* [Incident Response Playbooks](../playbooks/incident-response/index.md)
* [Critical CVE Response](../playbooks/operations/critical-cve-response.md)
* [Active Directory Hardening](../hardening/active-directory.md)
* [Detection and Analysis](detection-and-analysis.md), the next phase

## Resources

* [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
* [CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks](https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks)
* [Microsoft incident response playbooks](https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks)
* [CISA Tabletop Exercise Packages](https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages)
* Example incident response plans: [Carnegie Mellon University](https://www.cmu.edu/iso/governance/procedures/docs/incidentresponseplan1.0.pdf), [Wright State University](https://www.wright.edu/information-technology/policies)
