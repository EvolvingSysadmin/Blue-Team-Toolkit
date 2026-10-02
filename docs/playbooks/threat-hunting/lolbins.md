# Living Off the Land Binaries

## Hypothesis

An attacker is using built-in, Microsoft-signed Windows binaries to download payloads, run code, or bypass application controls, so no malicious file ever touches disk in a way that triggers antivirus.

## ATT&CK

* [T1218 System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
* [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
* [T1127.001 Trusted Developer Utilities Proxy Execution: MSBuild](https://attack.mitre.org/techniques/T1127/001/)

## Data

* EDR process telemetry: `DeviceProcessEvents`, `DeviceNetworkEvents`
* Sysmon Event ID 1 or Security 4688 with command line auditing

## Approach

These binaries are legitimate, so I hunt for the specific misuse patterns documented by the [LOLBAS project](https://lolbas-project.github.io/) rather than the binaries themselves.

Common misuse patterns:

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("urlcache", "-decode", "-encode", "http"))
    or (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("http", "javascript:", "vbscript:"))
    or (FileName =~ "regsvr32.exe" and ProcessCommandLine has_any ("/i:http", "scrobj.dll"))
    or (FileName =~ "rundll32.exe" and ProcessCommandLine has_any ("javascript:", "http", @"\AppData\", @"\Temp\"))
    or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has "/transfer")
    or (FileName =~ "msbuild.exe" and InitiatingProcessFileName !in~ ("devenv.exe", "dotnet.exe", "msbuild.exe"))
    or (FileName =~ "installutil.exe" and ProcessCommandLine has_any (@"\AppData\", @"\Temp\", @"\Users\Public\"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

These binaries making external network connections:

```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "msbuild.exe", "installutil.exe", "cmstp.exe")
| summarize Connections = count(), Destinations = make_set(RemoteUrl, 20) by DeviceName, InitiatingProcessFileName
```

## What Normal Looks Like

* `rundll32.exe` runs constantly for legitimate Windows and application DLLs; only command lines with URLs, script protocols, or user-writable paths are interesting
* `certutil.exe` is used by some admin scripts for certificate work, rarely for downloads
* `msbuild.exe` on developer workstations, launched by Visual Studio or build tools

Suspicious signs are: these binaries launched by Office applications, browsers, or script hosts; any of them downloading from the internet; and command lines pointing to `AppData`, `Temp`, or `Users\Public`.

## If I Find Something

I retrieve what was downloaded or executed and move to the [Endpoint Malware](../incident-response/endpoint-malware.md) playbook. Specific misuse patterns with few false positives become detections, and application control rules (WDAC or AppLocker) can block binaries that users never need.
