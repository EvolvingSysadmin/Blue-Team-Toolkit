# Dormant Accounts Becoming Active

## Hypothesis

An attacker is using an account that had gone unused: a former employee, a contractor, a test account, or an old service account. Nobody notices activity on an account nobody watches, and these accounts often have old, weak, or leaked passwords.

## ATT&CK

* [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/)
* [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)

## Data

* Entra ID `SigninLogs` with enough retention to see the dormant period (90 days or more)
* Domain Controller Security logs (4624) or Active Directory `lastLogonTimestamp`

## Approach

I look for accounts that signed in recently but had no sign-ins for a long period before that.

Cloud accounts active today after 60 or more days without a sign-in:

```kql
let recent = SigninLogs
    | where TimeGenerated > ago(1d) and ResultType == "0"
    | summarize FirstRecent = min(TimeGenerated), IPs = make_set(IPAddress, 10) by UserPrincipalName;
let prior = SigninLogs
    | where TimeGenerated between (ago(120d) .. ago(1d)) and ResultType == "0"
    | summarize PriorLast = max(TimeGenerated) by UserPrincipalName;
recent
| join kind=leftouter prior on UserPrincipalName
| where isnull(PriorLast) or PriorLast < ago(60d)
| project UserPrincipalName, FirstRecent, PriorLast, IPs
```

Enabled Active Directory accounts that have not logged on in 90 days, the list to watch and clean up:

```powershell
Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly |
    Where-Object Enabled |
    Get-ADUser -Properties LastLogonDate, PasswordLastSet, Description |
    Select-Object SamAccountName, LastLogonDate, PasswordLastSet, Description
```

`LastLogonDate` comes from `lastLogonTimestamp`, which replicates on a delay of up to about two weeks, so it is fine for finding stale accounts but not for exact last logon times.

## What Normal Looks Like

* Employees returning from leave
* New hires signing in for the first time (no prior sign-in at all)
* Seasonal or occasional users

Suspicious signs are: an account belonging to someone who has left, a sign-in from an IP or country the account never used before, or a test or shared account that suddenly signs in interactively.

## If I Find Something

I confirm with HR or the account owner's manager. Unauthorized use goes to the [Compromised Account / BEC](../incident-response/bec.md) playbook. Either way, the hunt usually ends with a list of accounts to disable, and a gap in the offboarding process to fix.
