# MFA Fatigue

## Alert

Repeated MFA push notifications sent to one user in a short period, especially several denials followed by an approval. Also reported directly by users: "I keep getting sign-in prompts I didn't ask for."

## Why It Matters

Repeated prompts mean the attacker already has the user's password. They are betting the user will approve one to make the prompts stop. Number matching makes this much harder, but users can still be talked into reading a number to an attacker posing as IT.

## ATT&CK

* [T1621 Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/)
* [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)

## Questions I Answer

1. **How many prompts, from which IPs, and when?** Prompts from an IP the user has never used, outside working hours, are the strongest sign.
2. **Did any prompt get approved?** A success after a run of denials is a compromise until proven otherwise.
3. **Did the user get a call or message** from someone claiming to be IT around the same time?
4. **What did the attacker do if they got in?** New MFA methods registered, inbox rules, sign-ins to other apps.

## Queries

Denied or failed MFA by user and hour (500121 is "strong authentication failed"):

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "500121"
| summarize Denials = count(), IPs = make_set(IPAddress, 10) by UserPrincipalName, bin(TimeGenerated, 1h)
| where Denials >= 3
| order by Denials desc
```

Success following denials for the same user:

```kql
let fatigued = SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == "500121"
    | summarize Denials = count(), LastDenial = max(TimeGenerated) by UserPrincipalName
    | where Denials >= 3;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| join kind=inner fatigued on UserPrincipalName
| where TimeGenerated > LastDenial - 1h
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, Denials
```

New MFA methods registered after the prompts:

```kql
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in ("User registered security info", "User changed default security info")
| extend Target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Target, Result
```

## Verdict

* **True positive, never approved:** the password is compromised. Reset it, revoke sessions, close after confirming nothing succeeded
* **True positive, approved:** account compromise
* **Benign:** an app on the user's own device repeatedly asking for re-authentication, from a known IP and device, confirmed by the user

## Escalate

[Compromised Account / BEC](../incident-response/bec.md) if any prompt was approved or new MFA methods appeared. Either way, the password has to be reset, because the attacker had it.
