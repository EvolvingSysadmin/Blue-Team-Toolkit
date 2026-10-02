# Suspicious PowerShell

## Alert

PowerShell launched with an encoded command, a hidden window, an execution policy bypass, or download-and-execute patterns. Fired by EDR, by Sysmon or 4688 process creation rules, or by script block logging (4104) detections.

## Why It Matters

PowerShell is one of the most common tools in malware delivery and hands-on-keyboard intrusions. It is also used by administrators, software installers, and management agents every day, so most of the work is separating the two.

## ATT&CK

* [T1059.001 Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
* [T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
* [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

## Questions I Answer

1. **What is the parent process?** PowerShell from an IT management agent, a deployment tool, or a scheduled task created by IT is usually expected. PowerShell from Word, Excel, Outlook, a browser, `wscript.exe`, `mshta.exe`, or an archive tool is not.
2. **What does the command actually do?** I decode any encoded command and read it (see below).
3. **Did it reach out to the internet?** Download cradles (`DownloadString`, `Invoke-WebRequest`, `Net.WebClient`) followed by a network connection to an unfamiliar domain are a strong sign.
4. **Did anything follow?** New files, child processes, persistence, or more PowerShell.
5. **Has this exact command line been seen before** on other hosts? A command that runs on hundreds of machines every day is probably a management tool.

## Decoding Encoded Commands

`-EncodedCommand` (or `-enc`, `-e`) takes Base64 of UTF-16LE text. To decode it safely, without running it:

```powershell
$encoded = "<base64 string>"
[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
```

CyberChef with "From Base64" followed by "Decode text (UTF-16LE)" does the same thing. Decoded scripts often contain another layer of encoding or compression.

## Queries

Suspicious PowerShell command lines and their parents:

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "FromBase64String", "DownloadString", "DownloadFile", "Invoke-WebRequest", "IEX", "Net.WebClient", "-w hidden", "-windowstyle hidden", "bypass")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine
```

How common is this command line across the fleet:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine == "<exact command line>"
| summarize Devices = dcount(DeviceName), FirstSeen = min(Timestamp), Parents = make_set(InitiatingProcessFileName)
```

Network connections from PowerShell on the host:

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where DeviceName =~ "WS-1234"
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
```

Script block logging content (Event ID 4104), when collected:

```kql
Event
| where TimeGenerated > ago(1d)
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| where Computer =~ "WS-1234"
| project TimeGenerated, Computer, RenderedDescription
```

## Verdict

* **Benign:** a known management tool or IT script, a consistent command line across many hosts, an expected parent, no unusual network activity
* **True positive:** an Office, browser, or script host parent; a download from an unfamiliar domain; decoded content that loads code into memory or disables security tools

## Escalate

[Endpoint Malware](../incident-response/endpoint-malware.md). If it was benign, I tune the detection on the parent process and command line, not on PowerShell as a whole.
