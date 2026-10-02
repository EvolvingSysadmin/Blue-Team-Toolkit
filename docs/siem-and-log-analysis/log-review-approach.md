# Log Review Approach

A general method for reviewing logs during an incident, based on the Critical Log Review Checklist for Security Incidents by Dr. Anton Chuvakin and Lenny Zeltser.

## Why It Matters

Logs are often the only record of what an attacker did, but an incident usually means a lot of logs from many sources, in different formats and time zones. A consistent approach keeps the review focused on answering questions instead of scrolling.

## Reference

### General Approach

| Step | Details |
| :--- | :--- |
| Identify sources | Which systems and tools have relevant logs |
| Centralize | Copy log records to one location, such as a SIEM or analysis workstation |
| Reduce noise | Filter out routine, repetitive entries |
| Normalize time | Confirm whether timestamps can be trusted and convert time zones to one standard, usually UTC |
| Focus | Recent changes, failures, errors, status changes, access and administration events, and anything unusual |
| Work backward | Start from the known event and go back in time to find the beginning |
| Correlate | Match activity across different logs by time, account, host, and IP |
| Test theories | Develop theories about what happened and look for evidence that confirms or disproves them |

### Security Log Sources

| Source | Examples |
| :--- | :--- |
| Operating systems | Windows event logs, Linux auth and syslog |
| Applications | Web servers, databases, business applications |
| Security tools | EDR, antivirus, IDS/IPS, change detection, email security |
| Network | Firewalls, VPN, proxy, DNS |
| Identity and cloud | Entra ID sign-in and audit logs, Microsoft 365 audit log, cloud provider audit logs |

### Typical Log Locations

| Platform | Location |
| :--- | :--- |
| Linux OS and core applications | `/var/log` and the systemd journal |
| Windows OS and core applications | Windows Event Log (Security, System, Application) |
| Network devices | Usually sent by syslog; some use proprietary formats |

## How I Use It

I write down the question I am trying to answer before I open a log, because "look through the logs" has no finish line. Then I start from the most reliable fact I have, such as the time an alert fired or a user's report, and work outward in time and across sources. Time zones catch me less often than they used to because I convert everything to UTC first.

## Related

* [Windows Event Logs](windows-event-logs.md)
* [Linux Logs](linux-logs.md)
* [Web Server Logs](web-server-logs.md)
* [Network Device Logs](network-device-logs.md)
* [Detection and Analysis](../incident-response/detection-and-analysis.md)

## Resources

* [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
