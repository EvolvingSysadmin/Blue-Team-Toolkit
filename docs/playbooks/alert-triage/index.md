# Alert Triage Runbooks

Short runbooks for the first ten to fifteen minutes with an alert. The goal is a verdict, not a full investigation: is this real, and does it need a playbook?

Each runbook covers:

* **Alert:** what fires it
* **Why it matters:** what an attacker gets if it is real
* **Questions I answer:** the checks, in order
* **Queries:** KQL to answer them
* **Verdict:** true positive, benign true positive (real activity, but authorized), or false positive
* **Escalate:** which playbook to run if it is real

## Runbooks

* [Impossible Travel](impossible-travel.md)
* [Password Spray](password-spray.md)
* [MFA Fatigue](mfa-fatigue.md)
* [Suspicious PowerShell](suspicious-powershell.md)
* [New Inbox Forwarding Rule](inbox-forwarding-rule.md)
* [New Privileged Account](new-privileged-account.md)
