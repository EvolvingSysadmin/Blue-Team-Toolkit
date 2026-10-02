# Windows Artifacts

* LNK files: shortcut files Windows creates when a user opens a file; they record the target path, timestamps, and volume information even after the target is deleted
  * Location: `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent`
  * Tools: [Windows File Analyzer](tools/windows-file-analyzer.md), LECmd (Eric Zimmerman)
* Prefetch files: created when an application runs; record the executable name and path, run count, last run times (up to eight on Windows 8 and later), and files and directories loaded
  * Location: `C:\Windows\Prefetch`
  * Prefetch is enabled by default on Windows client versions and usually disabled on Windows Server
  * Tool: [PECmd](tools/pecmd.md)
* Jump lists: per-application lists of recently and frequently opened files, stored as AutomaticDestinations-ms and CustomDestinations-ms files
  * Locations
    * `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`
    * `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations`
  * Tool: [JumpList Explorer](tools/jumplist-explorer.md)
* Browsers
  * Artifacts
    * Cookies
    * Favorites/bookmarks
    * Downloaded files
    * URLs visited
    * Searches
    * Cached pages and images
  * Tools for collecting artifacts
    * [KAPE](tools/kape.md)
    * [Browser History Capturer](tools/browser-history-capturer.md)
    * [Browser History Viewer](tools/browser-history-viewer.md)
* Logon Events
  * Event IDs
    * 4624: successful logon
    * 4625: failed logon
    * 4634: logoff
    * 4672: special privileges assigned (privileged account logon)
    * RDP logons: 4624 with logon type 10 (RemoteInteractive); also see the `Microsoft-Windows-TerminalServices-*` logs
  * Location: `C:\Windows\System32\winevt\Logs\Security.evtx`
  * More event IDs: [Windows Event Logs](../siem-and-log-analysis/windows-event-logs.md)
* Locations to check for anomalous files
  * Recycle Bin
  * `%TEMP%` (`C:\Users\<username>\AppData\Local\Temp`)
  * `C:\Users\<username>\Downloads`
  * `C:\Users\<username>\AppData` and `C:\ProgramData`
* Artifacts from CMD
  * Running tasks: `tasklist`
  * Running tasks with services: `tasklist /svc`
  * Output to text: `tasklist > tasklist.txt`
  * Users: `net user`
  * Users in the Administrators group: `net localgroup administrators`
  * All local groups: `net localgroup`
  * Users in a group: `net localgroup GROUP_NAME`
  * Services: `sc query | more`
  * Open ports with executables (requires administrator): `netstat -abno`
  * Note: `wmic` is deprecated and removed from current Windows 11 releases; use PowerShell instead
* Artifacts from PowerShell
  * Network information: `Get-NetIPConfiguration` or `Get-NetIPAddress`
  * Running processes with executable paths: `Get-Process | Select-Object Name, Id, Path`
  * Process command lines: `Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine`
  * Local users: `Get-LocalUser`
  * Details on a local user: `Get-LocalUser -Name JohnDoe | Select-Object *`
  * Running services: `Get-Service | Where-Object Status -eq "Running"`
  * Process priority: `Get-Process | Format-Table -View Priority`
  * Details on a process: `Get-Process -Id 1234 | Select-Object *` (or use `-Name`)
  * Find a process by name: `Get-Process | Where-Object Name -like "*calc*"`
  * Scheduled tasks: `Get-ScheduledTask`
  * Scheduled tasks in the Ready state: `Get-ScheduledTask | Where-Object State -eq "Ready"`
  * Details on a scheduled task: `Get-ScheduledTask -TaskName 'NAME' | Select-Object *`
  * Network connections: `Get-NetTCPConnection -State Established`
* Recycle Bin
  * Location
    * Windows Vista and later: `C:\$Recycle.Bin\<SID>`
    * Windows XP and earlier: `C:\RECYCLER`
  * Each deleted file creates a `$I` file (original path, size, deletion time) and a `$R` file (the contents)
  * Show hidden files: `dir /a` or `Get-ChildItem -Force`
  * Reference: <https://df-stream.com/2016/04/fun-with-recycle-bin-i-files-windows-10/>
* Processes
  * Know the normal parent-child relationships of core Windows processes so outliers stand out
  * Reference: <https://www.socinvestigation.com/important-windows-processes-for-threat-hunting/>
  * Examples of suspicious parent-child relationships
    * Office applications spawning `cmd.exe` or `powershell.exe`
    * PowerShell spawning another PowerShell process with an encoded command
  * Extract strings from an executable with Sysinternals Strings: `strings -a file_name.exe > strings_from_file.txt`
  * Dump a process for analysis with Sysinternals ProcDump: `.\procdump.exe -ma <PID>`
