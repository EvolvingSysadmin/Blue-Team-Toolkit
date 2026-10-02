# New Inbox Forwarding Rule

## Alert

A new or changed inbox rule that forwards or redirects mail, deletes it, or moves it to a rarely used folder; or mailbox-level forwarding (`ForwardingSmtpAddress`) set to an external address.

## Why It Matters

This is the most common persistence technique in business email compromise. Attackers forward a copy of everything to themselves, or quietly move replies from a vendor or customer into RSS Feeds or Archive so the real user never sees the conversation the attacker is having in their name.

## ATT&CK

* [T1114.003 Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)
* [T1564.008 Hide Artifacts: Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008/)

## Questions I Answer

1. **What does the rule do?** Forwarding to an external address, deleting messages, or moving them to RSS Feeds, Archive, Conversation History, or a new folder with a one-character name are the patterns I look for.
2. **What are the conditions?** Rules that match keywords like "invoice", "payment", "wire", "bank", or a specific vendor's domain are a strong BEC sign.
3. **Where was the rule created from?** The client IP on the audit event. If it matches a sign-in the user does not recognize, the account is compromised.
4. **Does the user know about it?** Some users do set up legitimate forwarding to a personal address, which is its own policy problem but not an intrusion.

## Queries

Rule and forwarding changes:

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox")
| where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "ForwardingSmtpAddress", "DeleteMessage", "MoveToFolder")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
```

Sign-ins from the IP that created the rule:

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where IPAddress == "203.0.113.10"
| project TimeGenerated, UserPrincipalName, Location, AppDisplayName, UserAgent, ResultType
```

Current state in Exchange Online PowerShell:

```powershell
Get-InboxRule -Mailbox user@example.com | Format-List Name, Enabled, From, SubjectContainsWords, BodyContainsWords, MoveToFolder, ForwardTo, RedirectTo, DeleteMessage
Get-Mailbox user@example.com | Format-List ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
```

## Verdict

* **True positive:** the user did not create it, or it was created from an unfamiliar IP, or it hides finance-related mail
* **Benign true positive:** the user created it intentionally; I still check it against policy on external forwarding
* **False positive:** a rule created by IT or a mail migration tool

## Escalate

[Compromised Account / BEC](../incident-response/bec.md). I export the rule details before removing it so the evidence is preserved.
