# Detection and Analysis

* Sources of detection: SIEM alerts, EDR alerts, IDS/IPS, user reports, third-party notifications, threat intelligence
* Validate the alert, determine scope, and assign severity
* Look for scanning and reconnaissance:
  * Remote to Local (R2L): external hosts probing internal systems, for example HTTP connections to non-standard ports
  * Remote to Local DoS/DDoS: traffic volumes that differ from baselines
  * Local to Local (L2L): internal scanning, which may be an authorized vulnerability scanner or an attacker performing discovery
* Look for authentication anomalies: failed logons (Windows Event ID 4625), logons from unusual locations or at unusual times, and explicit credential use (4648)
* Correlate across log sources and build a timeline
* Map observed activity to [MITRE ATT&CK](../threat-intelligence/mitre-attack.md) techniques
* Record findings, evidence, and actions as you go

## Related

* [Log Review Approach](../siem-and-log-analysis/log-review-approach.md)
* [Windows Event Logs](../siem-and-log-analysis/windows-event-logs.md)
* [Evidence Handling](../endpoint-forensics/evidence-handling.md)
