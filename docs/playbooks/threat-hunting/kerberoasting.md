# Kerberoasting

## Hypothesis

An attacker with any domain account has requested Kerberos service tickets for accounts with SPNs, to crack the service account passwords offline. Weak service account passwords would give them privileged access without any further exploitation.

## ATT&CK

* [T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)

## Data

* Domain Controller Security log Event ID 4769 (Audit Kerberos Service Ticket Operations must be enabled)
* Microsoft Defender for Identity, if deployed

## Approach

Normal clients request AES tickets for a small, stable set of services. Kerberoasting tools usually request RC4 (encryption type `0x17`) tickets, often for many services in a short time.

RC4 tickets for user-based service accounts:

```kql
SecurityEvent
| where TimeGenerated > ago(14d)
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$" and ServiceName !~ "krbtgt"
| summarize Tickets = count(), Services = dcount(ServiceName), ServiceList = make_set(ServiceName, 50) by TargetUserName, IpAddress, bin(TimeGenerated, 1h)
| order by Services desc
```

One account requesting tickets for many services:

```kql
SecurityEvent
| where TimeGenerated > ago(14d)
| where EventID == 4769
| where ServiceName !endswith "$" and ServiceName !~ "krbtgt"
| summarize Services = dcount(ServiceName) by TargetUserName, IpAddress, bin(TimeGenerated, 10m)
| where Services > 5
```

Which service accounts are exposed in the first place, from PowerShell with the ActiveDirectory module:

```powershell
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, "msDS-SupportedEncryptionTypes", AdminCount |
    Select-Object SamAccountName, PasswordLastSet, "msDS-SupportedEncryptionTypes", AdminCount, ServicePrincipalName
```

## What Normal Looks Like

* Older applications and appliances that only support RC4, always from the same hosts to the same services
* Monitoring and vulnerability scanning tools that enumerate SPNs on a schedule

Suspicious signs are: a workstation or regular user account requesting RC4 tickets for many services at once, or requests for service accounts that are rarely used.

## If I Find Something

I treat the targeted service accounts as compromised: reset their passwords to long random values (or move them to gMSAs) and follow the [Active Directory Privileged Compromise](../incident-response/ad-privileged-compromise.md) playbook for the requesting account. Even with no findings, the PowerShell output above usually produces a list of old passwords and privileged SPN accounts worth fixing.
