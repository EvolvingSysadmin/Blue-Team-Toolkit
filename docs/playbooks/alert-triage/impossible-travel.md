# Impossible Travel

## Alert

Successful sign-ins for the same account from two locations that are too far apart for the time between them (Entra ID Protection "Atypical travel" or "Impossible travel", Defender for Cloud Apps, or a custom rule).

## Why It Matters

It is one of the clearest signs of stolen credentials or a stolen session. It is also one of the noisiest alerts, because VPNs, mobile carriers, and cloud proxies move users' apparent locations around constantly.

## ATT&CK

* [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)

## Questions I Answer

1. **What are the two IPs?** A consumer VPN, a corporate VPN egress, a mobile carrier, or a hosting provider? Hosting provider and anonymizing VPN IPs on an account that does not normally use them are the strongest signal.
2. **Is the device the same?** The same device ID, browser, and OS in both locations points to VPN or proxy routing. A new device or an unusual user agent in one location does not.
3. **Did MFA happen, and how?** A sign-in that satisfied MFA from a token claim instead of a fresh prompt, from a new location, can mean a stolen session cookie.
4. **What happened after the sign-in?** Inbox rules, MFA method changes, file downloads, or mail sent from the unusual location.
5. **Does the user confirm it?** I ask by phone or chat, not email.

## Queries

The user's sign-ins around the alert:

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(2026-01-10 00:00) .. datetime(2026-01-11 00:00))
| where UserPrincipalName =~ "user@example.com"
| extend City = tostring(LocationDetails.city), DeviceId = tostring(DeviceDetail.deviceId), Browser = tostring(DeviceDetail.browser)
| project TimeGenerated, IPAddress, Location, City, AppDisplayName, DeviceId, Browser, UserAgent, ResultType, AuthenticationRequirement
| order by TimeGenerated asc
```

Is the unusual IP new for this user (30-day history):

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName =~ "user@example.com" and ResultType == "0"
| summarize SignIns = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by IPAddress, Location
| order by FirstSeen desc
```

Other users seen on the unusual IP:

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where IPAddress == "203.0.113.10"
| summarize SignIns = count() by UserPrincipalName, ResultType
```

## Verdict

* **False positive / benign:** same device in both locations and a known VPN or carrier IP, confirmed by the user
* **True positive:** a new device or hosting IP, the user denies it, or there is post-sign-in activity the user did not do

## Escalate

[Compromised Account / BEC](../incident-response/bec.md). If it was benign, I add the VPN egress range as a known location to cut future noise.
