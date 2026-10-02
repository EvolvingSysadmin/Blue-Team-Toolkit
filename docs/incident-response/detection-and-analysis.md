# Detection and Analysis

Deciding whether an event is an incident, how serious it is, and how far it reaches.

## Why It Matters

Everything after this phase depends on getting it right. Contain too early with a narrow scope and the attacker keeps the access you missed; take too long and they reach their objective. Good analysis answers what happened, which systems and accounts are involved, and whether the attacker is still active.

## Reference

### Detection Sources

| Source | Examples |
| :--- | :--- |
| Security tooling | SIEM alerts, EDR alerts, IDS/IPS, email security |
| Identity | Risky sign-in and risky user detections, MFA anomalies |
| People | User reports, help desk tickets, IT staff noticing something odd |
| External | Vendor or customer reports, law enforcement, threat intelligence, leak site monitoring |

### Analysis Steps

| Step | Questions |
| :--- | :--- |
| Validate | Is the alert accurate? Is the activity authorized? |
| Classify | What type of incident is it, and which playbook applies? |
| Scope | Which hosts, accounts, and data are involved? Is the attacker still active? |
| Prioritize | What severity, based on impact and how much is affected? |
| Timeline | When did it start, and what happened in what order? |
| Map | Which [ATT&CK](../threat-intelligence/mitre-attack.md) techniques were used, and what usually comes next? |

### Common Early Indicators

| Indicator | Where to Look |
| :--- | :--- |
| Scanning from outside (remote to local) | Firewall and IDS logs: many ports or hosts from one source, HTTP to non-standard ports |
| DoS / DDoS | Traffic volume compared to baseline |
| Internal scanning (local to local) | Firewall and EDR logs; confirm whether it is an authorized vulnerability scanner |
| Failed logons | Windows Event ID 4625, Entra ID sign-in failures |
| Explicit credential use | Windows Event ID 4648 |
| Logons from unusual locations or at unusual times | Entra ID sign-in logs, VPN logs |

!!! tip "Write it down as you go"
    Record findings, evidence locations, and actions with timestamps from the first minute. Reconstructing a timeline from memory at the end of a long incident is slow and unreliable.

## How I Use It

The first thing I do with any alert is decide whether it is real, using the matching [alert triage runbook](../playbooks/alert-triage/index.md) if there is one. Once it is confirmed, I pick the [playbook](../playbooks/incident-response/index.md), set a severity, and start a timeline.

Scoping is where I spend most of the time. One compromised account or infected host is rarely the whole story, so I pivot on everything I find: the attacker's IPs across all sign-ins, the malware hash across all endpoints, the phishing email across all mailboxes.

## Related

* [Alert Triage Runbooks](../playbooks/alert-triage/index.md)
* [Log Review Approach](../siem-and-log-analysis/log-review-approach.md)
* [Windows Event Logs](../siem-and-log-analysis/windows-event-logs.md)
* [Evidence Handling](../endpoint-forensics/evidence-handling.md)
* [Preparation](preparation.md), the previous phase; [Containment, Eradication, and Recovery](containment-eradication-recovery.md), the next

## Resources

* [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
* [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
