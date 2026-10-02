# Windows Artifacts

* LNK file analysis: LNK files are used by the Windows OS to link one file to another
  * LNK files can be found at: `C:\Users\$USER$\AppData\Roaming\Microsoft\Windows\Recent`
  * Windows File Analyzer can analyze these LNK files
* Prefetch files: useful information about programs including the name of the application, the path to the executable file, when the program was last run, and when the program was created/installed
  * Prefetch files are located at: `C:\Windows\Prefetch`
  * Prefetch Explorer Command Line (PECmd.exe) can be used to view these files
* Jump list: jump lists enable identification of filetypes automaticDestination-ms and customDestination-ms which show application pinned to the taskbar
  * Located here: `C:\Users\% USERNAME%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` and `C:\Users\%USERNAME%\AppData\ Roaming\Microsoft\Windows\Recent\CustomDestinations`
  * Use JumpList Explorer: <https://www.sans.org/tools/jumplist-explorer/>
* Browsers
  * Artifacts
    * Cookies
      * Favorites
      * Downloaded Files
      * URLs Visited
      * Searches
      * Cached Webpage
      * Cached Images
    * Tools for collecting artifacts
      * KAPE
      * Browser History Viewer
      * Browser History Capturer
* Logon Events
  * Log artifacts
    * Event ID 4624 (Successful Logon)
    * ID 4672 (Special Logon): privileged user login
    * ID 4625 (Failed Logon)
    * ID 4634 (Logoff)
    * RDP usage: Type 3 logon
  * Artifact Location
    * `C:\Windows\System32\winevt\Logs`
    * Stored in the \Security folder
* Directories to analyze for anamolous behavior
  * Recycle Bin
  * /tmp/
  * /Downloads
* Artifacts obtained through CMD
  * Tasks: `tasklist`
  * Ouput tasks to txt: `tasklist > tasklist.txt`
  * All running processes and associated binary files: `wmic process get description, executablepath`
  * Users: `net user`
  * Users in administrators group: `net localgroup administrators`
  * All groups: `net localgroup`
  * Users in group: `net localgroup GROUP_NAME`
  * Services detailed information: `sc query | more`
  * Open ports: `netstat -ab`
* Artifacts obtained through PowerShell
  * Network Information: `Get-NetIPConfiguration` or `Get-NetIPAddress`
  * Local users: `Get-LocalUser`
  * Information about local user: `Get-LocalUser -Name JohnDoe | select *`
  * Identify running services on the system: `Get-Service | Where Status -eq "Running" | Out-GridView`
  * Identify priority value of processes: `Get-Process | Format-Table View priority`
  * Info of specifiy services: `Get-Process -Id 'idhere' | Select *` can also use `-Name flag`
  * Scheduled tasks: `Get-ScheduledTask`
  * Scheduled tasks in ready state: `Get-ScheduledTask | Where State -eq "Ready"`
  * Specific scheduled task: `Get-ScheduledTask -TaskName 'NAME' | Select *`
* Artifacts from recycle bin
  * Location:
    * Windows 10: C:\$Recycle.Bin
    * XP or older: C:\Recycler
  * To display hidden files: `dir/a` or `Get-ChildItem -Hidden`
  * Reference: <https://df-stream.com/2016/04/fun-with-recycle-bin-i-files-windows-10/>
* Processes
  * Reference: <https://www.socinvestigation.com/important-windows-processes-for-threat-hunting/>
  * To search for strings within an exe by using sysinternals strings: `strings -a file_name.exe > strings_from_file.exe`

Windows Process Analysis

* A parent PowerShell process spawning a child PowerShell process can be indicative of a malicious script

PowerShell: `Get-Processes` | findstr -I calc
PowerShell: `Get-Processes | findstr -I calc`
Procdump: `.procdump.exe -ma PID_Number`
