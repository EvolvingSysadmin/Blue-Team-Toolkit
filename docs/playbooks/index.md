# Playbooks

These are the procedures I follow when something needs a response. The rest of this toolkit is reference material (event IDs, artifacts, tool usage); the playbooks are how I put it to work, and they link back to the reference pages instead of repeating them.

## Types

* **[Incident Response](incident-response/index.md):** what I do once an incident is confirmed, from triage through recovery
* **[Alert Triage](alert-triage/index.md):** short runbooks for deciding quickly whether a single alert is real
* **[Threat Hunting](threat-hunting/index.md):** hypothesis-driven searches for activity that did not trigger an alert
* **[Operations](operations/index.md):** recurring security work that keeps the defenses healthy

## How the Playbooks Are Written

* Queries are written in KQL (Microsoft Sentinel and Defender XDR advanced hunting) because that is where identity and email evidence usually lives. The logic carries over to other platforms; for Splunk, see my [SPL repo](https://github.com/EvolvingSysadmin/Splunk-Tools).
* Table and column names follow the Sentinel and Defender XDR schemas. Adjust them if your data arrives through a different connector.
* Time windows and thresholds in the queries are starting points. Tune them to the environment.

## Incident Response Playbook Template

Every incident response playbook follows the same structure:

1. **Scope and triggers:** what starts the playbook
2. **Severity:** how I decide between low, medium, high, and critical
3. **ATT&CK mapping:** the techniques usually involved
4. **Data sources:** the logs and tools I need
5. **Flow:** a decision diagram of the main path
6. **Triage, Containment, Eradication, Recovery:** numbered steps with the decision points called out
7. **Queries:** KQL for scoping and hunting
8. **Communication:** who I notify and when
9. **Close-out:** evidence to retain, lessons learned, and detections to add
