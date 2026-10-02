# Windows Artifacts

Where Windows records evidence of program execution, file access, and user activity, plus commands for live response.

## Why It Matters

Windows keeps records of what ran, what was opened, and what was deleted, often long after the files themselves are gone. These artifacts let an investigator reconstruct activity on a host even without EDR, and confirm or fill gaps in what EDR recorded.

## Reference

### Execution and File Access

| Artifact | Location | What It Shows | Tool |
| :--- | :--- | :--- | :--- |
| Prefetch | `C:\Windows\Prefetch` | Programs that ran, run count, last run times (up to eight on Windows 8 and later), files loaded | [PECmd](tools/pecmd.md) |
| LNK files | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent` | Files a user opened, with target path and timestamps, even if the target was deleted | LECmd, [Windows File Analyzer](tools/windows-file-analyzer.md) |
| Jump lists | `...\Recent\AutomaticDestinations` and `...\Recent\CustomDestinations` | Recently and frequently opened files for each application | [JumpList Explorer](tools/jumplist-explorer.md) |
| Recycle Bin | `C:\$Recycle.Bin\<SID>` (Vista and later), `C:\RECYCLER` (XP) | Deleted files: `$I` files hold the original path, size, and deletion time; `$R` files hold the contents | RBCmd |
| Browser history | Browser profile folders | URLs visited, downloads, searches, cached content | [KAPE](tools/kape.md), [Browser History Capturer](tools/browser-history-capturer.md) and [Viewer](tools/browser-history-viewer.md) |
| Event logs | `C:\Windows\System32\winevt\Logs` | Logons, process creation, services, and more | See [Windows Event Logs](../siem-and-log-analysis/windows-event-logs.md) |

Prefetch is enabled by default on Windows client versions and usually disabled on Windows Server.

### Logon Evidence

| Event ID | Meaning |
| :--- | :--- |
| 4624 | Successful logon (RDP logons are logon type 10) |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4672 | Special privileges assigned (privileged account logon) |

RDP activity also appears in the `Microsoft-Windows-TerminalServices-*` logs.

### Locations to Check for Suspicious Files

* Recycle Bin
* `%TEMP%` (`C:\Users\<user>\AppData\Local\Temp`)
* `C:\Users\<user>\Downloads`
* `C:\Users\<user>\AppData` and `C:\ProgramData`
* `C:\Users\Public`

### Live Response: Command Prompt

| Task | Command |
| :--- | :--- |
| Running processes | `tasklist` |
| Processes with their services | `tasklist /svc` |
| Users | `net user` |
| Members of Administrators | `net localgroup administrators` |
| Local groups | `net localgroup` |
| Services | `sc query | more` |
| Connections and listening ports with executables (administrator) | `netstat -abno` |

`wmic` is deprecated and removed from current Windows 11 releases; use PowerShell instead.

### Live Response: PowerShell

| Task | Command |
| :--- | :--- |
| Network configuration | `Get-NetIPConfiguration` |
| Processes with executable paths | `Get-Process | Select-Object Name, Id, Path` |
| Process command lines and parents | `Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine` |
| Find a process by name | `Get-Process | Where-Object Name -like "*calc*"` |
| Established network connections | `Get-NetTCPConnection -State Established` |
| Local users | `Get-LocalUser` |
| Details on one user | `Get-LocalUser -Name JohnDoe | Select-Object *` |
| Running services | `Get-Service | Where-Object Status -eq "Running"` |
| Scheduled tasks | `Get-ScheduledTask` |
| Details on one task | `Get-ScheduledTask -TaskName 'NAME' | Select-Object *` |
| Hidden files | `Get-ChildItem -Force` |

### Process Relationships

Knowing normal parent-child relationships makes the abnormal ones stand out:

| Normal | Suspicious |
| :--- | :--- |
| `services.exe` -> `svchost.exe` | `svchost.exe` with any other parent |
| `wininit.exe` -> `lsass.exe` (one instance) | More than one `lsass.exe`, or one in the wrong path |
| `explorer.exe` -> user applications | Office applications, browsers, or `wscript.exe` -> `cmd.exe` or `powershell.exe` |

## How I Use It

On a live host, I start with the PowerShell process and connection commands to see what is running and talking right now, then collect artifacts with [KAPE](tools/kape.md) or EDR live response before making any changes. Prefetch and Amcache tell me what ran; LNK files, jump lists, and shellbags tell me what the user opened; the event logs tie it to accounts and times. I parse it all to CSV and build one timeline.

For anything suspicious, I pull strings with Sysinternals Strings (`strings -a file.exe > strings.txt`) and, if needed, dump the process with ProcDump (`.\procdump.exe -ma <PID>`). See [Sysinternals](tools/sysinternals.md).

## Related

* [Windows Event Logs](../siem-and-log-analysis/windows-event-logs.md)
* [Endpoint Malware](../playbooks/incident-response/endpoint-malware.md) playbook
* [Persistence](../playbooks/threat-hunting/persistence.md) hunt
* [KAPE](tools/kape.md), [PECmd](tools/pecmd.md), [Sysinternals](tools/sysinternals.md)

## Resources

* [Eric Zimmerman's Tools](https://ericzimmerman.github.io/)
* [Fun with Recycle Bin $I files](https://df-stream.com/2016/04/fun-with-recycle-bin-i-files-windows-10/)
* [Important Windows Processes for Threat Hunting](https://www.socinvestigation.com/important-windows-processes-for-threat-hunting/)
* [SANS DFIR Posters and Cheat Sheets](https://www.sans.org/posters/)
