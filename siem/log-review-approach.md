# Log Review Approach

* Description: critical log review checklist developed by Dr. Anton Chuvakin and Lenny Zeltser
* General Approach
  * Identify which log sources and automated tools
  * Copy log records to a single location
  * Minimize “noise” by removing routine, repetitive log entries
  * Determine whether you can rely on logs' time stamps; consider time zone differences (data normalization)
  * Focus on recent changes, failures, errors, status changes, access and administration events, and other unusual events
  * Go backwards in time from now to reconstruct actions after and before the incident
  * Correlate activities across different logs
  * Develop theories about what occurred; explore logs to confirm or disprove
* Security Log Sources
  * Server and workstation operating system logs
  * Application logs (e.g., web server, database server)
  * Security tool logs (e.g., anti-virus, change detection, intrusion detection/prevention system)
  * Outbound proxy logs and end-user application logs
  * Remember to consider other, non-log sources for security events
* Typical Log Locations
  * Linux OS and core applications: /var/log
  * Windows OS and core applications: Windows Event Log (Security, System, Application)
  * Network devices: usually logged via Syslog; some use proprietary locations and formats
* Resouces
  * [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
  * [Critical Log Review Checklist for Security Incidents PDF](../assets/security-incident-log-review-checklist.pdf)
  * [Open Source Log Analysis Tools](http://www.securitywarriorconsulting.com/logtools/)
  