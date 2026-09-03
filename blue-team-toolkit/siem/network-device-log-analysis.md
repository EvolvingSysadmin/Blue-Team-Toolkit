# Network Device Log Analysis

* Description: list of items to consider for network device forensic analysis
* What to scrutinize
  * Look at both inbound and outbound activities.
* Examples below show log excerpts from Cisco ASA logs; other devices have similar functionality:
  * Traffic allowed on firewall: “Built … connection”, “access-list … permitted”
  * Traffic blocked on firewall: “access-list … denied”, “deny inbound”, “Deny … by”
  * Bytes transferred (large files?): “Teardown TCP connection … duration … bytes …”
  * Bandwidth and protocol usage: “limit … exceeded”, “CPU utilization”
  * Detected attack activity: “attack from”
  * User account changes: “user added”, “user deleted”, “User priv level changed”
  * Administrator access: “AAA user …”, “User … locked out”, “login failed”
* Resources
  * [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
