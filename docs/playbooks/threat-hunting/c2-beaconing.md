# C2 Beaconing

## Hypothesis

Malware on a host is checking in with a command and control server at a regular interval, over HTTPS or DNS, to infrastructure that has no reputation yet and so does not trigger blocklist alerts.

## ATT&CK

* [T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
* [T1071.004 Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
* [T1573 Encrypted Channel](https://attack.mitre.org/techniques/T1573/)

## Data

* EDR network telemetry: `DeviceNetworkEvents`
* Proxy and firewall logs, DNS logs

## Approach

Beacons repeat at a fixed interval with a small random variation (jitter). I look for connections from the same process to the same destination where the time between connections is very consistent.

Connections with low variation in interval:

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize Connections = count(), Times = make_list(Timestamp, 2000) by DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl
| where Connections > 50
| mv-apply t = Times to typeof(datetime) on (
    order by t asc
    | extend Delta = datetime_diff("second", t, prev(t))
    | summarize AvgDelta = avg(Delta), StdDelta = stdev(Delta))
| where StdDelta < AvgDelta * 0.2
| project DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, Connections, AvgDelta, StdDelta
| order by Connections desc
```

Destinations contacted by very few hosts (rare destinations are more interesting than popular ones):

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public" and isnotempty(RemoteUrl)
| summarize Hosts = dcount(DeviceName), Connections = count(), Processes = make_set(InitiatingProcessFileName, 5) by RemoteUrl
| where Hosts <= 2 and Connections > 100
| order by Connections desc
```

## What Normal Looks Like

Plenty of legitimate software beacons: update checkers, EDR and antivirus agents, chat clients, cloud storage sync, telemetry. I filter by process and destination after confirming each one, and keep that list for the next hunt.

Suspicious signs are: an unsigned or oddly located process, `rundll32.exe`, `powershell.exe`, or a script host making the connections, a recently registered domain, a destination only one host talks to, or a direct-to-IP connection with no DNS lookup.

## If I Find Something

I look up the destination's reputation and registration date, then check the process on the host. Confirmed C2 goes to the [Endpoint Malware](../incident-response/endpoint-malware.md) playbook, and I search for the same destination across all hosts.
