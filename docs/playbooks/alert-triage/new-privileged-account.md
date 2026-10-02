# New Privileged Account

## Alert

An account was added to a privileged Active Directory group (Domain Admins, Enterprise Admins, Administrators, and similar) or assigned a privileged Entra ID role (Global Administrator, Privileged Role Administrator, Exchange Administrator, and similar), or a new account was created and given privileges shortly after.

## Why It Matters

Granting privilege to an account the attacker controls is a common step right before ransomware deployment or data theft, and a common persistence method afterward. It is also a normal admin task, so the question is whether it was authorized.

## ATT&CK

* [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/)
* [T1136 Create Account](https://attack.mitre.org/techniques/T1136/)
* [T1078.002 Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

## Questions I Answer

1. **Who made the change, and from where?** The actor account, the host or IP, and the time.
2. **Is there a change ticket or request?** And does the actor confirm it, asked by phone or chat, not email?
3. **Who received the privilege?** A brand-new account, a service account, a disabled account that was re-enabled, or an account with a name that imitates a real admin are all warning signs.
4. **What did the account do after it got privileges?**

## Queries

Active Directory privileged group changes:

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728, 4732, 4756)
| where TargetUserName in~ ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators", "Server Operators")
| project TimeGenerated, Computer, Actor = SubjectUserName, MemberAdded = MemberName, Group = TargetUserName
```

Entra ID role assignments:

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add member to role", "Add eligible member to role")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend Target = tostring(TargetResources[0].userPrincipalName)
| mv-apply prop = TargetResources[0].modifiedProperties on (
    where tostring(prop.displayName) == "Role.DisplayName"
    | extend Role = trim('"', tostring(prop.newValue)))
| project TimeGenerated, Actor, Target, Role, Result
```

Accounts created and granted privileges within a day (Active Directory):

```kql
let created = SecurityEvent
    | where TimeGenerated > ago(7d) and EventID == 4720
    | project Created = TimeGenerated, AccountSid = TargetSid, NewAccount = TargetUserName, CreatedBy = SubjectUserName;
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728, 4732, 4756)
| project Granted = TimeGenerated, AccountSid = MemberSid, Group = TargetUserName, GrantedBy = SubjectUserName
| join kind=inner created on AccountSid
| where Granted between (Created .. (Created + 1d))
| project Created, Granted, NewAccount, Group, CreatedBy, GrantedBy
```

The query joins on the account SID, because the group membership events record the member as a distinguished name rather than the account name.

## Verdict

* **Benign true positive:** a documented change by an admin who confirms it
* **True positive:** no ticket, the actor denies it, or the actor account itself shows signs of compromise
* **Process gap:** a real admin made the change without a ticket; not an intrusion, but worth fixing

## Escalate

[Active Directory Privileged Compromise](../incident-response/ad-privileged-compromise.md) for on-premises changes, or [Compromised Account / BEC](../incident-response/bec.md) for an Entra ID role assigned by a compromised cloud account. I remove the privilege immediately if the change is unauthorized, after recording the details.
