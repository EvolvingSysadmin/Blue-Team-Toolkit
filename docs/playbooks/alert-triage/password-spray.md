# Password Spray

## Alert

Failed sign-ins for many different accounts from the same source in a short period, usually with one or two common passwords per account to stay under lockout thresholds. Fired by Entra ID Protection, Defender for Identity, or a custom rule on failed logons.

## Why It Matters

Password spraying works against any organization with weak or reused passwords. The alert matters less than the answer to one question: did any of the attempts succeed?

## ATT&CK

* [T1110.003 Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

## Questions I Answer

1. **Which source IPs, and how many accounts did each try?** Many accounts from one IP is spraying; many failures for one account is brute force or a stale saved password.
2. **Did any attempts succeed?** I check for successful sign-ins from the same IPs, during and after the spray.
3. **Were the targeted accounts valid?** Attempts against real usernames mean the attacker has a valid user list, often from a previous breach or from the company website.
4. **Was MFA the only thing that stopped a correct password?** A failure at the MFA step (rather than a bad password) means the password was right and that account needs a reset.
5. **Is it on-premises too?** I check Domain Controller 4625 events and VPN logs, not just cloud sign-ins.

## Queries

Spray sources (bad password and smart lockout results):

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType in ("50126", "50053")
| summarize Accounts = dcount(UserPrincipalName), Attempts = count(), SampleAccounts = make_set(UserPrincipalName, 10) by IPAddress
| where Accounts > 10
| order by Accounts desc
```

Any success or correct password from those sources:

```kql
let sprayIPs = SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType in ("50126", "50053")
    | summarize Accounts = dcount(UserPrincipalName) by IPAddress
    | where Accounts > 10
    | project IPAddress;
SigninLogs
| where TimeGenerated > ago(1d)
| where IPAddress in (sprayIPs)
| where ResultType == "0" or ResultType in ("50074", "50076", "500121")
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription, AppDisplayName
```

Result type 0 is a successful sign-in. 50074 and 50076 mean MFA was required, and 500121 means MFA failed; all three mean the password was correct.

On-premises failed logons by source:

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625
| summarize Accounts = dcount(TargetUserName), Attempts = count() by IpAddress, Computer
| where Accounts > 10
```

## Verdict

* **True positive, no success:** block the source IPs, confirm lockout and smart lockout settings, close
* **True positive with a correct password or success:** those accounts are compromised or one step away
* **Benign:** a misconfigured application or service account cycling through accounts (usually an internal IP and the same failure every few minutes)

## Escalate

[Compromised Account / BEC](../incident-response/bec.md) for every account where the password was correct, even if MFA blocked the sign-in. Those passwords need to be reset.
