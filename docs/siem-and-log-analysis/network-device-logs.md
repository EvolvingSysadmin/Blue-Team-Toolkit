# Network Device Logs

Firewall and network device log messages worth reviewing during an investigation.

## Why It Matters

Firewalls and other network devices see traffic that endpoints and identity logs do not: scanning against the perimeter, connections to attacker infrastructure, and the volume of data leaving the network. They also log changes to the devices themselves, which are high-value targets.

## Reference

The examples below are Cisco ASA log messages; other vendors log similar events with different wording.

| Activity | Example Log Text |
| :--- | :--- |
| Traffic allowed | "Built ... connection", "access-list ... permitted" |
| Traffic blocked | "access-list ... denied", "deny inbound", "Deny ... by" |
| Bytes transferred (large transfers) | "Teardown TCP connection ... duration ... bytes ..." |
| Bandwidth and resource usage | "limit ... exceeded", "CPU utilization" |
| Detected attack activity | "attack from" |
| Account changes | "user added", "user deleted", "User priv level changed" |
| Administrator access | "AAA user ...", "User ... locked out", "login failed" |

## How I Use It

I review both directions. Inbound denies show who is scanning or attacking the perimeter; outbound allows show which internal hosts talked to attacker infrastructure and how much data left. Administrator logins and configuration changes on the devices themselves get checked in every investigation that involves the network edge.

## Related

* [Syslog](syslog.md)
* [Exploited Edge Device](../playbooks/incident-response/edge-device-exploitation.md) playbook
* [C2 Beaconing](../playbooks/threat-hunting/c2-beaconing.md) hunt

## Resources

* [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
