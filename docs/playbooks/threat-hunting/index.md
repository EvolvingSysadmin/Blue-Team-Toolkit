# Threat Hunting

Hunts start from a hypothesis about attacker behavior that existing alerts might miss, then look for evidence for or against it. A hunt that finds nothing is still useful: it confirms visibility and usually produces a new detection or a list of benign activity to baseline.

Each hunt covers:

* **Hypothesis:** what I think an attacker might be doing
* **ATT&CK:** the techniques involved
* **Data:** what I need to see it
* **Approach and queries:** how I look, in KQL
* **What normal looks like:** the benign results I expect and how I filter them
* **If I find something:** where it goes next

## Hunts

* [Persistence: Scheduled Tasks, Services, and Run Keys](persistence.md)
* [Kerberoasting](kerberoasting.md)
* [C2 Beaconing](c2-beaconing.md)
* [Living Off the Land Binaries](lolbins.md)
* [Dormant Accounts Becoming Active](dormant-accounts.md)

## After Every Hunt

1. Record the hypothesis, data used, queries, findings, and time spent
2. Turn anything with a low enough false positive rate into a scheduled detection
3. Note visibility gaps (missing logs, hosts without EDR) and raise them
