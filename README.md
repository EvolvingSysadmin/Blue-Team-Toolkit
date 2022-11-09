# DFIR Toolkit
Documentation for Digital Forensics and Incident Response Tools and Techniques

## TOC
* Incident Response
    * [Incident Response Lifecycle](#incident-response-lifecycle)
    * [MITRE ATT&CK Framework](#mitre-attck-framework)
* Network Analysis
    * [Basic Network Tools](#basic-network-tools)
    * [Basic Port Info](#basic-port-info)
    * [NMAP](#nmap)
    * [Wireshark](#wireshark)
* Phishing Analysis
    * [Basic Email Info](#basic-email-info)
    * [Email Headers](#email-headers)
* Systems Forensics
    * [Digital Evidence Handling](#digital-evidence-handling)
    * [Basic File Metadata](#basic-file-metadata)
    * [File Hashing](#file-hashing)
    * [File Systems](#file-systems)
    * [Memory File Analysis](#memory-file-analysis)
    * [Windows Artifacts](#windows-artifacts)
    * [Linux Artifacts](#linux-artifacts)
    * [FTK Imager](#ftk-imager)
    * [Exiftool](#exiftool)
    * [Scalpel](#scalpel)
    * [KAPE](#kape)
    * [Windows File Analyzer](#windows-file-analyzer)
    * [Prefetch Explorer Command Tool PECmd.exe](#prefetch-explorer-command-tool-pecmdexe)
    * [JumpList Explorer](#jumplistexplorer)
    * [Browser History Viewer](#browser-history-viewer)
    * [Browser History Capturer](#browser-history-capturer)
    * [John the Ripper](#john-the-ripper)  
    * [Steghide](#steghide)
    * [Volatility](#volatility)
    * [Autopsy](#autopsy)
    * [YARA](#yara)
* Security Information and Event Monitoring
    * [Log Review Approach](#log-review-approach)
    * [Windows Log Analysis](#windows-log-analysis)
    * [Linux Log Analysis](#linux-log-analysis)
    * [Web Server Log Analysis](#web-server-log-analysis)
    * [Network Device Log Analysis](#network-device-log-analysis)
    * [Syslog](#syslog)
    * [Sysmon](#sysmon)
    * [Splunk](#splunk)
    * [DeepBlueCLI](#deepbluecli)
    * [Sysinternals](#sysinternals)
    * [Other Tools](#other-tools)

## Incident Response Lifecycle
* Incident Response Lifecycle: Preparation -> Detection and Analysis -> Containment, Eradication, and Recovery -> Lessons Learned and Reporting
* Phases
    * Preparation
        * Incident Response Plans Should Include the Following Sections:
            * Preparation
            * Identification
            * Containment
            * Eradication
            * Recovery
            * Lessons Learned
        * Example Incident Response Plans
            * [Carnegie Mellon University](https://www.cmu.edu/iso/governance/procedures/docs/incidentresponseplan1.0.pdf)
            * [Wright State University](https://www.wright.edu/information-technology/policies)
        * Create Incident Response Team and conduct training and create incident response run books
            * [Microsoft Run Books](https://docs.microsoft.com/en-us/security/compass/incident-response-playbooks)
            * [Run book examples](https://www.incidentresponse.org/playbooks/)
        * Create asset-inventories
        * Run risk assessments
        * Enact defensive measures, eg DMZ, NIDS/HIDS/NIPS, AV, Centralized Logging, EDR, Network Firewalls, Local Firewalls, WAFs, GPOs, NAC, web proxies, SPF/DKIM/DMARC, mark external emails, use email spam filters, DLP, sandboxing, attachment file restrictions, physical defenses, awareness training, phishing simulations, etc...
    * Detection and Analysis
        * Identify scanning, including:
            * Remote to Local Scanning (R2L): Search for HTTP connections of non standard ports
            * Remote to Local DoS/DDoS (L2R): search for anamolus traffic that differs from baselines
            * Local to Local Scanning (L2L): internal vulnerability scanners
            * Login Failures: search for windows event ID 4625
    * Containment
        * Perimeter containment
            * Block inbound traffic and outbound traffic.
            * IDS/IPS Filters to identify further malicious traffic and take automated actions, such as blocking active connections.
            * Web Application Firewall policies, to detect and take action against web attacks.
            * Null route DNS, to prevent DNS resolutions so internal hosts cannot find the IP address of a given domain name and establish a connection.
        * Network containment
            * Switch-based VLAN isolation, to restrict network access.
            * Router-based segment isolation, to restrict network access.
            * Port blocking, to prevent connections on specific ports.
            * IP or MAC Address blocking, to restrict network access.
            * Access Control Lists (ACLs), to provide rules that restrict what hosts on the network can and cannot do.
        * Endpoint containment
            * Disconnecting the infected system from any network connections (turning WiFi off, pulling ethernet cable).
            * Powering off the infected system.
            * Blocking rules in the local firewall.
            * Host intrusion prevention system (HIPS) actions, such as device isolation.
    * Eradication
        * Remove malicious artifacts
        * Reimage systems
    * Recovery
        * Identify root cause
        * Patch systems
        * Disable uneeded services
        * Update EDR, AV, IDPS, and SIEM rules
        * Share intelligence 
    * Lessons Learned and Reporting
        * Post incident review meetings: what could be improved
        * Create report that should contain
            * Executive Summary
            * Incident Timeline
            * Incident Investigation
            * Appendix
        * Report considerations
            * Report Audience
            * Incident Investigation
            * Screenshots and Captions

## MITRE ATT&CK Framework
* MITRE ATT&CK Framework Stages: https://attack.mitre.org/matrices/enterprise/ 
    * MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
* Initial access 9 techniques:
    * [Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
    * [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
    * [External Remote Services](https://attack.mitre.org/techniques/T1133/)
    * [Hardware Additions](https://attack.mitre.org/techniques/T1200/)
    * [Phishing](https://attack.mitre.org/techniques/T1566/)
    * [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/)
    * [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
    * [Trusted Relationship](https://attack.mitre.org/techniques/T1199/)
    * [Valid Accounts](https://attack.mitre.org/techniques/T1078/)
* Execution technique examples: https://attack.mitre.org/tactics/TA0002/
    * [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
    * Administrative feature of windows, WMI service used for local and remote access to SMB and the Remote Procedure Call Service (RPCS), MITRE provides specific identification of WMI
    * [User Execution](https://attack.mitre.org/techniques/T1204/)
* Persistence examples: https://attack.mitre.org/tactics/TA0003/
    * [Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
    * [External Remote Services](https://attack.mitre.org/techniques/T1133/)
        * EG SSH, FTP, VPN
* Privilege escalation examples: https://attack.mitre.org/tactics/TA0004/
    * [Valid Accounts](https://attack.mitre.org/techniques/T1078/)
        * Obtaining valid accounts (eg via phishing)
    * [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
* Defense evasion: https://attack.mitre.org/tactics/TA0005/
    * Ways that adversaries will work to evade or disable security defenses such as antivirus, endpoint detection and response, logging, and human analysts 
    * Impair defenses: disrupting operation of security tools (eg SIEM)
        * Disable of Modify Tools
        * Disable Windows Event Logging
        * HISTCONTROL (used to not log command history) which affects `~/.bash_history`
        * Disable or Modify System Firewall 
        * Indicator Blocking
        * Disable or Modify Cloud Firewall 
    * Indicator removal: 
        * Deleting bash history
        * Deleting files
        * Deleting raw log files
        * Timestomping 
* Credential access: https://attack.mitre.org/tactics/TA0006/
    * [OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
        * LSASS Memory: credentials stored in memory, eg using Mimikatz
        * Monitor lsass.exe in Windows
        * Use AuditD for Linux
        * /etc/passwd /etc/shadow: dumping /etc/passwd and /etc/shadow (only accessible by root) files for password cracking 
    * [Brute Force](https://attack.mitre.org/techniques/T1110/)
        * Hashcat can be used to attack encrupted passwords using brute force: https://hashcat.net/hashcat/
        * Mitigations: account lockout policies, better passwords, MFA, log monitoring
* Discovery: https://attack.mitre.org/tactics/TA0007/
    * Account discovery:
        * Local accounts: `net user` and `net localgroup` (windows), `id` and `groups` (MacOS), `/etc/passwd` using `cat`, `string` or `head` (Linux)
        * Domain accounts: `net user /domain` and `net group domain` (windows), `dscacheutil -q group` (MacOS), `ldapsearch` (linux)
        * Email and cloud accounts
        * Mitigations: disable the registry key to prevent administrator accounts from being enumerated, group policy can force this change network-wide
    * Network service discovery
    * File and directory discovery
* Lateral movement: https://attack.mitre.org/tactics/TA0008/
    * Enumerating internal remote services, eg:
        * Remote Desktop Protocol (RDP)
        * SMB/Windows Admin Shares
        * Distributed Component Object Model
        * SSH
        * VNC
        * Windows Remote Management (WINRM)
        * Mitigating enumeration: use MFA, monitor timelines of logon activity
    * Internal spearphishing, eg using a script to email other users from a compromised systems emali client
        * Scan eamil/attachments for mitigation
* Collection: https://attack.mitre.org/tactics/TA0009/
    * Email collection
    * Audio capture
    * Screen capture
    * Data from local system
    * Mitigations: audit, encryption, MFA, monitor api calls releated to system audio, monitor unusual processes that access microphones, API calls taking screenshots
    * Data from local system mitigation: monitor for commands such as dir, find, tree, locate; monitor for excessive usage of commands in CMD and powershell related to exfiltration
* Command and control: https://attack.mitre.org/tactics/TA0011/
    * Application layer using protocols like http, https, dns
    * Cobalt strike is an example of a C2 application  
       * Mitigation: NIDS/NIPS, monitor network data flows
    * Web service: legit web services may be used for C2
    * Nonstandard ports: C2 typically uses ports that aren't associated with services
        * Mitigation: restrict proxies/firewall ports for outbound connections, packet inspection
* Exfiltration: https://attack.mitre.org/tactics/TA0010/
    * Exfil Over C2 Channel
        * Mitigation: frequency analysis
    * Scheduled transfer
        * Mitigation: NIPS/NIDS
* Impact: https://attack.mitre.org/tactics/TA0040/
    * EG disrupting availability and intergrity
        * Account access removal:
        * Deleting or locking accounts
        * Password changes
        * Mitigation: windows log monitoring, baseline comparison
        * Defacement:
        * Delivering messaging,
        * Intimidation
        * Claiming credit for an intrusion
        * Mitigation: revert to latest backup, WAF to monitor websites, defend against SQL injection and cross site scripting
        * Data encryption (eg ransomware):
        * Mitigations: data backups, monitor specific command-line usages such as vssadmin, wbadmin, bcdedit

## Basic Network Tools
* IP information
    * Windows: `ipconfig /all`
    * Linux: `ip -aip r`
* Routing tables
    * Windows: `route print`
    * Linux: `ip r list`
* Traceroute
    * Windows: `tracert [URL]`
    * Linux: `traceroute [url] -p [port number]`
* DNS
    * Windows: `nslookup [domain name]`
    * Linux: `dig [domain name]`
    * Linux email DNS info: `dig [domain name] mx`
    * Linux get A record: `dig [domain name] ANY +nocomments +noauthority +noadditional +nostats`
* Netstat
    * Windows and Linux current connections/listening ports: `netstat -a`
    * Windows current connections/ports/related executables: `netstat -a -b`
    * Windows and Linux statistics for all connections using TCP: `netstat -s -p tcp -f`
* PING
    * Linux: `sudo ping -v [target]`
    * Linux ping summary: `ping -c 5 -q [target]`

## Basic Port Info
* Port Ranges
    * Well-known ports: 0 to 1023
    * Registered ports: 1024 to 49151
    * Private ports: 49152 to 65535
* Common Ports:
    * FTP: 20, 21
    * SSH: 22
    * Telnet: 23
    * SMTP: 25
    * DNS: 53
    * DHCP: 67, 68
    * HTTP: 80
    * HTTPS: 443
    * Syslog (UDP): 514
    * RDP: 3389

## NMAP
| Option      | Full Command | Description    |
| :---        |    :----:   |          ---: |
| -v     | nmap -v [target]       | Verbose output  |
| -O     | nmap -O [target]       | OS detection   |
| -sS    | nmap -sS [target]      | Fast scan
| -sT    | nmap -sT [target]      | Half-scan, doesn't complete tcp handshake |
| -sU    | nmap -sU [target]      | Full scan, completeds tcp handshake
| -sA    | nmap -sA [target]      | Firewall identification
| -sV    | nmap -sV [target]      | Finds service on each responding port

## Wireshark
* Description: used to capture and analyze network traffic in the form of packet capture files
* Installation: download from https://www.wireshark.org/#download 
* Usage
    * Basic Capture Filter Examples
        * Capture Filters
        * Limit traffic to and from IP address: `host 192.168.1.1`
        * All traffic on the subnet: `net 192.168.0.0/24:`
        * Packets sent to the specified host: `dst host 192.168.1.1`
        * Limit traffic to port 53 only: `port 53`
        * All traffic except DNS/ARP: `port not 53 and not arp`
    * Basic Display Filter Examples
        * Packets sent from one computer (ip.src) to another (ip.dst): `ip.src==IP-address and ip.dst==IP-address`
        * Show you all traffic on port 25 (typically SMTP): `tcp.port eq 25`
        * Only show ICMP traffic: `icmp`
        * All traffic except traffic from specified IP: `ip.addr != IP_address`
        * Traffic from src host using TCP 443, using TLC version 1.2: `ip.src_host == 192.168.1.7 and tcp.port == 443 and ssl.record.version == 0x0303`
        * Show specific HTTP method: `http.request.method == "POST"`
        * Search for a string within a frame: `frame contains "string"`
        * Search strings within packets: CTRL + F
        * Host Identification from DHCP traffic: `ip.src==xxx.xxx.xxx && dhcp` then search for Host Name in the DHCP Options of a DHCP request packet
        * Search for http redirection: `http.reaspon.code==301` or search for the http.referer field
        * More Display Filters here: https://wiki.wireshark.org/DisplayFilters
    * More Advanced Searching
        * To follow a packet stream: Right Click -> Follow > TCP/UDP/SSL/HTTP Stream
        * To extract HTTP files from packets: File -> Export Objects -> HTTP -> Highlight File -> Save As
        * To extract FTP files from packets: filter FTP-DATA packets for export -> Right Click -> Follow > TCP Stream -> Show and save data as Raw
        * To extract files from streams: Follow TCP Stream -> Save stream as raw -> Analyze with exif-tools or change file extension
            * Example: `frame contains 20210429_152157.jpg” -> Follow TCP Stream -> Save stream as raw` -> then analyze with exif-tools or change file extension to view
        * To search for domain names: Statistics -> Search for IP
        * To identify hostnames from DHCP traffic: `ip.src==xxx.xxx.xxx.xxx && dhcp` -> search for Host Name in the DHCP Options of a DHCP request packet
        * To search for http redirction: `http.response.code==301` or search for the http.referer field
        * Helpful Windows
            * Conversations
            * Protocol Hierarchy
            * Endpoints
* Resources
    * [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
    * [Wireshark Training Resources](https://www.wireshark.org/docs/)
    * [Into to Wireshark Video](https://www.youtube.com/watch?v=jvuiI1Leg6w)
    * [Wireshark Tutorial](https://www.varonis.com/blog/how-to-use-wireshark)
    * [Export Wireshark Data from TCP Stream](https://medium.com/@sshekhar01/cyberdefenders-packetmaze-beffc1d05cb)
    * [Identifying Hosts and Users using Wireshark](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)

## Basic Email Info
* Email Protocols
    * Simple Mail Transfer Protocol (SMTP): Port 25 by default, Port 587 for TLS
    * Post Office Protocol 3 (POP3): Port 110 by default, Port 995 for TLS
    * Internet Mail Access Protocol (IMAP): Port 143 by default, Port 993 for TLS
* Email Security Measures
    * Sender Policy Framework (SPF): a type of DNS (TXT) record that can help prevent an email address from being forged by sending alerts
    * Domain Keys Identified Mail (DKIM): cryptographically verifies if an email has been sent by its trusted servers and wasn't tampered during transmission
    * Domain-based Message Authentication, Reporting and Conformance (DMARC): email authentication, policy and reporting protocol that specifies what happens upon SPF and DKIM failure
* Types of Malicious Emails
    * Spam Recon Emails: identifying if email error codes are sent back
    * Social Engineering Recon Emails: attempting to get response
    * Tracking Pixel Recon Emails: see if the email has been viewed by an email client (track OS, email website, client, screen resolution, date/time of read, IP address)
    * Spam email
    * Links to credential harvesters, domains with typo squatting, shortened urls
* Email Spoofing
    * From address may look legitimate but whois lookup of X-Originating-IP shows different organization
    * Reply-To address may be different than sender address
    * HTML styling
* Common Email Artifacts
    * Sending Address
    * Subject Line
    * Recipient(s)
    * Date and Time
    * Sending Server IP
    * Reverse DNS of Sending Server IP
    * Reply-To (if present)
    * Links/a hrefs (IP and root domain of those links)
    * File Attachment name
    * File attachment SHA256 HASH
* Common Malicious Email Attachment File Types
    * .exe (Executable)
    * .vbs (Visual Basic Script)
    * .js (JavaScript)
    * .iso (Optical Disk Image)
    * .bat (Windows Batch File)
    * .ps/.ps1 (PowerShell Scripts)
    * .htm/.html (Web Pages / Hypertext Markup Language)
* Email anslysis resources
    * Domain/IP Lookup: https://whois.domaintools.com/ 
    * Domain Registration Lookup: https://lookup.icann.org/en 
    * URL Analysis: https://urlhaus.abuse.ch/ 
    * Show root HTTP Response: https://www.wannabrowser.net/
    * Reverse IP Lookup: https://mxtoolbox.com/ReverseLookup.aspx 
    * IP Geolocation: https://www.iplocation.net/
    * URL Sandbox: https://urlscan.io/ 
    * Track reported phishing data: https://phishtank.org/ 
    * Virustotal Malware Analysis: https://www.virustotal.com/gui/home/upload
    * Talos Malware Analysis: https://talosintelligence.com/talos_file_reputation 
    * Hybrid Analysis Malware Analysis: https://www.hybrid-analysis.com/ 

## Email Headers
* Standard Headers
    * From, showing the sender's email address
    * To, showing the recipient's email address
    * Date, showing the date when the email was sent.
* Optional Headers
    * Received, showing various information about the intermediary servers and the date when the message was processed
    * Reply-To, showing a reply address
    * Delivered-To displays the recipient’s name and address, as well as other addresses present in the CC and BCC
    * From: IP address/other details about sender
    * subject showing the message's subject
    * message-ID, showing a unique identification for the message
    * message body, containing the message, separated from the header by a line break
    * Return-Path: return address in case of email failure
    * Content-Type field indicates whether the format of an email was HTML, TXT, or any other option
    * Received-SPF: sender verification
    * Authentication-Results: ID of authentication performing server
    * DKIM Signature: details of the sender, message, and the public key which is required to perform message authentication
* Custom X-Headers
    * X-Received: non-standard headers added by some email providers
* Header Lists/Guides
    * [IANA Email Message Headers List](https://www.iana.org/assignments/message-headers/message-headers.xhtml) 
    * [Email Header Quick Reference Guide](https://jkorpela.fi/headers.html) 
    * [Email Header Guide](https://mailtrap.io/blog/email-headers/)
    * [Email headers: What they are & how to read them](https://www.mailjet.com/blog/deliverability/how-to-read-email-headers/)
    * [Email Header Analysis and its application in Email Forensics](https://www.stellarinfo.com/article/email-header-structure-forensic-analysis.php)

## Digital Evidence Handling
* Digital Evidence Process: Identification -> Preservation -> Collection -> Analysis -> Reporting
* Forms of Digital Evidence:
    * Email
    * Digital Photographs
    * Logs
    * Documents
    * Messages
    * Files
    * Browser History
    * Databases
    * Backups
    * Disk Images
    * Video/audio files
* Digital evidence handling tenants:
    * No altering of original evidence
    * Use write-blockers
    * Document the process
* Order of Volatility: olatile data includes running memory or the Address Resolution Protocol (ARP) cache
    * Registers & Cache: CPU cache contents
    * Memory: RAM contents
    * Disk (HDD and SSD)
    * Remote Logging and Monitoring Data
    * Physical Configuration, Network Topology, Archival Media
* Follow chain of custody by:
    * Using Evidence Integrity Hashing
    * Taking a Forensic Copy
    * Storing Digital Evidence securely
    * Using Chain of Custody Form

## Basic File Metadata
* Windows
    * Right click file -> Properties -> Details
    * PowerShell: `Get-ChildItem .\path-to-file.jpg | Format-List *`
    * PowerShell Get-FileMetaData Function: https://gist.github.com/woehrl01/5f50cb311f3ec711f6c776b2cb09c34e
* Linux
    * `ls -lisap <file>`
    * `stat <file>`

## File Hashing
* Linux
    * Get hash of text string: `echo -n 'This is the text' | md5sum`
        * Example: `echo -n "This is the text" | md5sum`
    * Get hash of file
        * `sha256sum <file>`
        * `sha1sum <file>`
        * `md5sum <file>`
        * Examples
            * `sha256sum hashthis.jpg`
            * `sha256sum hashthis.jpg && sha1sum hashthis.jpg && md5sum hashthis.jpg`
* Windows
    * `Get-FileHash -Algorithm <algorithm> .\file_path`
        * Examples
            * `Get-FileHash -Algorithm sha1 .\hashthis.jpg`
            * `get-filehash .\file.exe ; get-filehash -algorithm md5 .\file.exe ; get-filehash -algorithm sha1 .\file.exe`

## File Systems
* FAT16: File Allocation Table, uses a table to mark the position of the files; used by DOS and Windows 3.X; files can be lost of the FAT is lost/damaged
* FAT32: FAT16 but with larger partitions for long filenames; uses 32 bits of data for identifying data clusters
    * FAT32 is compatable with many devices and is cross compatible with all modern operating systems since 1995
    * FAT32 disadvantages:
        * Only >4GB files
        * 8TB max capacity
        * No data protection from power loss
        * No built in compression
        * No built in encryption
* NTFS: Microsoft file system since Windows NT 3.1
    * Improved performance, reliability, security (ACLs) and disk space from FAT
* Linux architecture for EXT3 and EXT4
    * User space: user space -> sends to system call -> requeast sent to kernel
    * Kernel space: operating system core -> provides requested resources to user space, manages io/memory/file management
    * Disk space: kernal space device driver io request -> hard disk
* EXT3/EXT4
    * EXT3: default file system for many popular Linux distributions; uses journaling for resiliency
    * EXT4: maximum volume size of data supported by ext4 is 1exbibyte and file size is up to 16 tebibytes; uses extents which is a data storage area that reduces file fragmentation and file scattering
* FTK Imager can be used to show file types of disk images

## Memory File Analysis
* Pagefile.sys: used within Windows operating systems to store data from the RAM when it becomes full
    * Pagefile Location: `C:\pagefile.sys`
    * To show the hidden pagefile: `dir /a:h c:`
* Swapfile used as RAM swap space in Linux, usually in its own partition
    * To adjust swapfile size: `sudo fallocate -l [file size] /swapfile`
    * To check the ammount of swap space: `free -h`
    * To show if the swap space is a file or a partition`swapon –show` 
* Hiberation file: allows operating system to store current memory state to `hiberfil.sys`

## Windows Artifacts
* LNK file analysis: LNK files are used by the Windows OS to link one file to another
    * LNK files can be found at: `C:\Users\$USER$\AppData\Roaming\Microsoft\Windows\Recent`
    * Windows File Analyzer can analyze these LNK files
* Prefetch files: useful information about programs including the name of the application, the path to the executable file, when the program was last run, and when the program was created/installed
    * Prefetch files are located at: `C:\Windows\Prefetch`
    * Prefetch Explorer Command Line (PECmd.exe) can be used to view these files
* Jump list: jump lists enable identification of filetypes automaticDestination-ms and customDestination-ms which show application pinned to the taskbar
    *  Located here: `C:\Users\% USERNAME%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` and `C:\Users\%USERNAME%\AppData\ Roaming\Microsoft\Windows\Recent\CustomDestinations`
    *  Use JumpList Explorer: https://www.sans.org/tools/jumplist-explorer/
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
    * Reference: https://df-stream.com/2016/04/fun-with-recycle-bin-i-files-windows-10/ 
* Processes
    * Reference: https://www.socinvestigation.com/important-windows-processes-for-threat-hunting/ 
    * To search for strings within an exe by using sysinternals strings: `strings -a file_name.exe > strings_from_file.exe`

## Linux Artifacts
* Password Hashes
    * Passwd file: `/etc/passwd` file is used to keep track of every registered user that has access to a system
    * Shadow file: `/etc/shadow` file contains encrypted passwords as well as other information such as account or password expiration values
        * To show shadow file content: `sudo cat /etc/shadow`
* Installed Software
    * Find installed software on Debian based systems by checking the status file: `/var/lib/dpkg/status`
    * Save all lines that contain package in `/var/lib/dpkg/status` to packages.txt: `cat status | grep Package > packages.txt`
* System Logs
    * `/var/log/auth.log`: system authorizations, including user logins
    * `/var/log/dpkg.log`: packages installed or removed using the `dpkg` command
    * `/var/log/btmp`: failed login attempts
    * `/var/log/cron`: cron jobs
    * `/var/log/secure`: authentication and authorization privileges (eg related to SSH)
    * `/var/log/faillog`: failedf user logins
* Web Server Logs for Apache and Nginx
    * `var/log/apache2/access.log`: shows web server info in Apache, including:
        * Client IP
        * Resource accessed
        * HTTP method
        * User-Agent of client IP
        * Request timestamps
* User Files
    * Bash History
        * `cd ~`
        * `ls -a`
        * `cat .bash_history`
        * `history` can also be used, but `history -c` can be used to delete terminal history
    * Clear Files
        * Desktop, Downloads, Music, Pictures, Public, Templates, Videos
        * Trash Bin
    * Super user startup scripts: `/etc/rc.local`

## FTK Imager
* Description: tool for dumping memory to a .mem file, taking disk images, exporting files from disk images, generating MD5/SHA1 hashes for evidence, provides read only view of contents of disk image
* Installation: can be downloaded from https://accessdata.com/product-download-page 
* Usage
    * To capture memory and save it to a .mem file: File -> Capture Memory
    * To create a .img file : File -> Create Disk Image
    * To inspect a disk image file: Add Evidence -> Image File
* Resources
    * [Comprehensive Guide on FTK Imager](https://www.hackingarticles.in/comprehensive-guide-on-ftk-imager/)

## Exiftool
* Description: used to get file metadata, can be used to extract strings from metadata
* Linux Installation: `sudo apt-get install exiftool`
* Windows Installation: download from https://exiftool.org/ 
* Usage
    * To retrieve file metadata: `exiftool <filename>`
    * To embed "sneaky!" into dpg.jpg: `exiftool -Comment="sneaky!" dog.jpg` -> this creates file with embedded text called `dog.jpg_original`
* Resources
    * [ExifTool FAQ](https://exiftool.org/faq.html)
    * [Exiftool Installation](https://exiftool.org/install.html)
    * [Exiftool Linux Man Page](https://linux.die.net/man/1/exiftool)
    * [Online Exiftool](https://exif.tools/)
    * [Another Online Exiftool](http://exif-viewer.com/)
    * [Exporting DData from TCP Stream](https://medium.com/@sshekhar01/cyberdefenders-packetmaze-beffc1d05cb)

## Scalpel
* Description: used to retrieve deleted files from .img files by using file carving
* Linux installation: `sudo apt-get install scalpel`
* Usage
    * Edit scalpel.conf to uncomment the type of files hoping to get from an .img file by doing one of the following
        * Manually edit the file by using the GUI to navigate to:  `/etc/scalpel/scalpel.conf` and uncomment relevent file types
        * Use vim or nano `sudo nano /etc/scalpel/scalpel.conf` and uncomment relevent file types
        * Create a copy of the `/etc/scalpel/scalpel.conf`, uncomment relevent file types, and then specify that file when using scalpel by using: `scalpel -c /path/to/new/conf.conf`
    * Create an empty output directory
    * Run command: `scalpel -b -o /empty/output/directory DiskImage.img` 
        * Example: `scalpel -b -o /root/Desktop/ScalpelOutput DiskImage1.img`
    * Note: scalpel can be configured to search for document types with custom headers and footers by editing the configuration file:
        * Example for files with "BTL1" header and "1LTB" footer: create a new line on the .conf file with `txt y 10000 BTL1 1LTB`
        * To show strings from a recovered file: `strings path\to\txt`
* Resources
    * [https://linux.die.net/man/1/scalpel](Scalpel Man Page)
    * [Kali Tool Description](https://www.kali.org/tools/scalpel/)
    * [Scalpel Guide](https://www.tecmint.com/install-scalpel-a-filesystem-recovery-tool-to-recover-deleted-filesfolders-in-linux/)

## KAPE
* Description: triage program that will target essentially any device or storage location, find forensically useful artifacts, and parse them within a few minutes, also provides browser forensic artifacts
* Installation: download from https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape
* Usage: Run gkape.exe for the GUI tool -> Select Target Source -> Select Output Directory -> Select Targets (eg Chrome)
* Resources
    * [How to use Kape for Fast and Flexible Incident Response](https://www.giac.org/paper/gcih/34611/kape-fast-flexible-incident-response/152146)
    * [KAPE Docs](https://github.com/EricZimmerman/KapeDocs)

## Windows File Analyzer
* Description: decodes and analyzes useful Windows OS files (eg LNK Files) for forensic analysis
* Installation: download program at https://www.mitec.cz/wfa.html 
* Usage: File -> Analyze shortcut
* Resources
    * [Background and basic usage](https://www.portablefreeware.com/index.php?id=2298)

## Prefetch Explorer Command Tool PECmd.exe 
* Description: used to fetch all possible forensic artifacts from a Windows prefetch file, which can be used to investigate applciations executed on a system
* Installation: download program at https://ericzimmerman.github.io/#!index.md
* Usage:
    * On single file: `PECmd.exe -f "C:\tmp\calc.exe-asdfasd.pf"`
    * On directory: `PECmd.exe -d "C:\tmp\pfdirectory\"`
    * To run a string match in a directory: `PECmd.exe -k “plaguerat.ps1” -d "C:\Users\BTLOTest\Desktop\Windows Investigation One\Prefetch\"`
        * Example: `PECmd.exe -k “plaguerat.ps1” -d "C:\Users\BTLOTest\Desktop\Windows Investigation One\Prefetch\"`
* Resources
    * [PECmd.cmd Documentation](https://github.com/EricZimmerman/PECmd)

## JumpListExplorer
* Description: used to analyze LNK files to identify application information related to a user's profile
* Installation: can be downloaded from https://www.sans.org/tools/jumplist-explorer/
* Usage: File -> Load Jump Lists
  * JumpList files are located here: 
        * `C:\Users\% USERNAME%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`
        * `C:\Users\%USERNAME%\AppData\ Roaming\Microsoft\Windows\Recent\CustomDestinations`
* Resources
    * [GitHub Repo](https://github.com/EricZimmerman/JumpList)

## Browser History Capturer
* Description: can be used in conjunction with Browser History Viewer to obtain browser artifacts
* Installation: download program from https://www.foxtonforensics.com/browser-history-capturer/
* Usage: select user profile -> select browsers -> select data -> select output directory -> capture -> use Browser History Viewer to analyze

## Browser History Viewer
* Description: used to retrieve browser information
* Installation: download program from https://www.foxtonforensics.com/browser-history-viewer/ 
* Usage: File -> Load History from output directory of Browser History Capture

## John the Ripper
* Description: used to crack password hashes, including passwords from the passwd and shadow files in Linux
* Installation: `sudo apt-get install john`
* Usage
    * Obtain Linux password hashes from shadow file: `cat /etc/shadow`
    * To combine passwd and shadow files: `unshadow passwd shadow > HashFile`
    * To run using HashFile as input and rockyou.txt as word list with both files in current directory: `john HashFile --wordlist=rockyou.txt`
* Resources
    * [John the Ripper Usage Examples](https://www.openwall.com/john/doc/EXAMPLES.shtml)
    * [John the Ripper Tutorial](https://www.varonis.com/blog/john-the-ripper)
    * [Additional Downloads for different Operating Systems](https://www.openwall.com/john/)
    * [Word Lists](https://www.openwall.com/passwords/wordlists/)
    * [Rock You Word List](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)

## Steghide
* Description: used to hide and retrieve files, files can be easily hidden using steganography by running something like `cat Dog.jpg secretmessage.zip > Dog2.jpg` which hides the zip inside the jpg file
* Installation: `sudo apt-get install steghide`
* Usage
    * To hide secretmessage.txt inside dog.jpg: `steghide embed -cf dog.jpg -ef secretmessage.txt`
        * `embed `: specifies operation
        * `-cf dog.jpg`: cover file using dog.jpg
        * `-ef secretmessage.txt`: embedded file using secretmessage.txt
    * To extract hidden file: `steghide extract -sf dog.jpg`
        * `extract`: specifies operation
        * `-sf dog.jpg`: steganogrphy flag to specify file with potentially hidden data
* Resources
    * [Steghide Website](https://steghide.sourceforge.net/)
    * [Steghide Download](https://steghide.sourceforge.net/download.php)
    * [Steghide Manual](https://steghide.sourceforge.net/documentation/manpage.php)
    * [Steghide Tutorial](https://linuxhint.com/steghide-beginners-tutorial/)

## Volatility
* Description: used for memory forensics and has the following capabilities:
    * List all processes that were running
    * List active and closed network connections
    * View internet history (IE)
    * Identify files on the system and retrieve them from the memory dump
    * Read the contents of notepad documents
    * Retrieve commands entered into the Windows Command Prompt (CMD)
    * Scan for the presence of malware using YARA rules
    * Retrieve screenshots and clipboard contents
    * Retrieve hashed passwords
    * Retrieve SSL keys and certificates
    * Find executables/commands related to processes
    * Export processes
* Installation: 
    * Can be downloaded and installed from https://www.volatilityfoundation.org/releases
        * Extract archive and run `setup.py`
    * Can be cloned from repo by using: `git clone https://github.com/volatilityfoundation/volatility.git`
        * On Linux, extract archive and run: `sudo python setup.py install`
* Usage
    * Create Profile
        * Run volatility on memory dump: `volatility -f memdump.mem imageinfo`
        * Any other commands need to include profile: `--profile=WinXPSP2x86`
    * Volatility Commands
        * `volatility -f memdump.mem imageinfo`: take memory image “memdump.mem” and determine the suggested profile (OS version and architecture) for analysis
        * `volatility -f memdump.mem --profile=PROFILE pslist`: use pslist plugin to print a list of processes to the terminal
        * `volatility -f memdump.mem --profile=PROFILE pstree`: use pstree plugin to print a process tree to the terminal
        * `volatility -f memdump.mem --profile=PROFILE psscan`: use psscan plugin to print all available processes,
        * `volatility -f memdump.mem --profile=PROFILE psxview`: use psxview plugin to print expected and hidden processes
        * `volatility -f memdump.mem --profile=PROFILE netscan`: use netscan plugin to identify any active or closed network connections
        * `volatility -f memdump.mem --profile=PROFILE timeliner`: use timeliner plugin to create a timeline of events from the memory image
        * `volatility -f memdump.mem --profile=PROFILE iehistory`: use iehistory plugin to pull internet browsing history
        * `volatility -f memdump.mem --profile=PROFILE filescan`: use filescan plugin to identify any files on the system from the memory image
        * `volatility -f memdump.mem --profile=PROFILE dumpfiles -n --dump-dir=./`: use dumpfiles plugin to retrieve files from the memory image, outputs files to current directory
        * `volatility -f memdump.mem --profile=PROFILE procdump -n --dump-dir=./`: use procdump plugin to dump process executables from the memory image, outputs to current directory

    * Volatility Examples
        * `python vol.py -f /home/ubuntu/Desktop/Volatility\ memdump1.mem imageinfo`: identify memory sample information like system architecture
        * `python vol.py -f /home/ubuntu/Desktop/Volatility\ memdump1.mem --profile=Win7SP1x64 pslist | grep “svchost.exe”`: find processes using volatility and pipe output into grep to search for lines containing "svchost.exe"
        * `python vol.py -f /home/ubuntu/Desktop/Volatility\ memdump1.mem --profile=Win7SP1x64 pslist | grep “svchost.exe” | wc -l`: outputs wordcount of number of ""svchost.exe" services identified by volatility
        * `python vol.py -f /home/ubuntu/Desktop/Volatility\ memdump1.mem --profile=Win7SP1x64 dlllist -p 2352`: find command line arguments used by process 2352
        * `python vol.py -f /home/ubuntu/Desktop/Volatility\ Exercise/memdump2.mem --profile=Win7SP1x64 procdump -p 2940 --dump-dir /path/to/output/directory`: dumps the executable for process 2940 to current directory
* Resources
    * [Volatility Reference Guide](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
    * [Volatility Downloads](https://www.volatilityfoundation.org/releases)
    * [Volatility Installation](https://github.com/volatilityfoundation/volatility/wiki/Installation)
    * [Volatility Wiki](https://github.com/volatilityfoundation/volatility/wiki)
    * [Volatility Documentation](https://volatility3.readthedocs.io/en/latest/)
    * [Volatility GitHub](https://github.com/volatilityfoundation/volatility/wiki/Installation)
    * [Memory Samples for Test Analysis](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)
    * [Volatility Cheat Sheet](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-examples)
    * [Another Volatility Cheat Sheet](https://blog.onfvp.com/post/volatility-cheatsheet/)
    * [Volatility Tutorial](https://medium.com/@zemelusa/first-steps-to-volatile-memory-analysis-dcbd4d2d56a1)

## Autopsy
* Description: comprehensive forensics tool that has the following capabilities:
    * Keyword Search
    * Timeline Analysis
    * LNK File Analysis
    * Email Analysis
    * File Type Sorting
    * Media Playback
    * Thumbnail viewer
    * Robust File System Analysis
    * Hash Set Filtering
    * Unicode string extraction
    * File type detection
    * Interesting files module
    * Android support
* Installation: can be downloaded from https://www.autopsy.com/download/ 
* Usage: open Autopsy -> Select Data Source -> Choose modules -> Analyze results
* Resources
    * [Autopsy User Guide](http://sleuthkit.org/autopsy/docs/user-docs/4.19.3/)

## YARA
* Description: identifying specific files by looking at the characteristics of a large number of files to see if any of them match the profile
* Installation
    * On Linux: download tar file from https://github.com/virustotal/yara/releases/tag/v4.0.2 
         * Install dependencies: `sudo apt-get install automake libtool make gcc pkg-config`
         * Install YARA: `tar -zxf yara-4.0.2.tar.gz` -> `cd yara-4.0.2/` -> `./bootstrap.sh`
         * Compile YARA: `./configure` -> `make` -> `sudo make install`
         * Confirm Installation: `sudo make install`
* Usage
    * Write YARA Rules: https://yara.readthedocs.io/en/stable/writingrules.html 
    * Run rule file against a target: `yara [OPTIONS] RULES_FILE TARGET`
    * YARA Flags
        * -m: Prints the associated meta information to the terminal after a YARA scan.
        * -s: Prints the matching strings to the terminal after a YARA scan.
        * -r: Recursively scan all subfolders within the target location to ensure everything is scanned.
    * YarGen to automatically generate rules for files: https://github.com/Neo23x0/yarGen/releases 
        * Installation
            * `YarGen: tar -zxf yarGen-0.18.0.tar.gz`
            * `sudo apt-get install python-pip`
            * `sudo pip install pefile cd`
            * `sudo pip install scandir lxml naiveBayesClassifier`
            * `python yarGen.py --update`
            * `python yarGen.py --help`
        * Usage
           * `python yarGen.py -m /root/Desktop/Malware -o ./TestRule.yara`
           * `python yarGen.py`: Runs the yarGen python script 
           * `-m /root/Desktop/Malware`: Create rules for files inside the Malware folder
           * `-o ./TestRule.yara`: Output the generated rule to the current folder
           * `cat TestRule.yara`: read rules
* Resources: 
    * https://yara.readthedocs.io/en/stable/gettingstarted.html
    * https://yara.readthedocs.io/en/stable/writingrules.html
    * https://yara.readthedocs.io/en/stable/commandline.html 
    * https://github.com/Yara-Rules/rules

## Log Review Approach
* Description: critical log review checklist developed by Dr. Anton Chuvakin and Lenny Zeltser
* General Approach
    * Identify which log sources and automated tools
    * Copy log records to a single location
    * Minimize “noise” by removing routine, repetitive log entries
    * Determine whether you can rely on logs' time stamps; consider time zone differences (data normalization)
    * Focus on recent changes, failures, errors, status changes, access and administration events, and other unusual events
    * Go backwards in time from now to reconstruct actions after and before the incident
    * Correlate activities across different logs
    * Develop theories about what occurred; explore logs to confirm or disprove
* Security Log Sources
    * Server and workstation operating system logs
    * Application logs (e.g., web server, database server)
    * Security tool logs (e.g., anti-virus, change detection, intrusion detection/prevention system)
    * Outbound proxy logs and end-user application logs
    * Remember to consider other, non-log sources for security events
* Typical Log Locations
    * Linux OS and core applications: /var/log
    * Windows OS and core applications: Windows Event Log (Security, System, Application)
    * Network devices: usually logged via Syslog; some use proprietary locations and formats
* Resouces
    * [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
    * [Critical Log Review Checklist for Security Incidents PDF](./docs/security-incident-log-review-checklist.pdf)
    * [Open Source Log Analysis Tools](http://www.securitywarriorconsulting.com/logtools/)

## Windows Log Analysis
* Description: Windows event IDs that help in log analysis. Most events are in the Security log, many only logged on Domain Controller
    * “Windows Event logs” or “Event Logs” are files in binary format (with .evtx extension), stored here:
        * Windows 2000 to WinXP/Windows Server 2003: `%WinDir%\system32\Config*.evt`
        * Windows Server 2008 to 2019, and Windows Vista to Win10: `%WinDir%\system32\WinEVT\Logs*.evtx`
* Event Log Categories
    * Application: Events logged by an application (Execution, Deployment error, etc.)
    * System: Events logged by the Operating System (Device loading, startup errors, etc.)
    * Security: Events that are relevant to the security of the system (Logins and logouts, file deletion, granting of administration permissions, etc.)
    * Directory Service: This is a record available only to Domain Controllers, it stores Active Directory (AD) events
    * DNS Server: It is a record available only to DNS servers; logs of DNS service are stored
    * File Replication Service: Is a record available only for Domain Controllers, it stores Domain Controller Replication events
* Events
    * User logon/logoff
        * Successful logon: 528, 540, 4624, 5379
        * Failed logon: 529-537, 539, 4625
        * Logoff: 538, 551, 4672, 4634, 4647
        * Special Logon: 4672
        * Logon attempt with explicit credentials: 4648
        * Replay attack detected: 4649
    * User account changes
        * Created 624, 4720
        * Enabled 626
        * Changed 642
        * Disabled 629
        * Deleted 630. 4726
        * Memeber added to security enabled group: 4732
    * Password changes	
        * To self: 628
        * To others: 627
        * Password reset: 4724
    * File access events
        * A handle to an object was requested with intent to delete: 4659
        * A handle to an object was requested: 4656
        * The handle to an object was closed: 4658
        * An object was deleted: 4660
        * An attempt was made to access an object: 4663
        * The state of a transaction has changed: 4685
        * The state of a transaction has changed: 4985
    * Anamolous events
        * Service started or stopped: 7035, 7036
        * Object access denied (if auditing enabled): 560, 567
        * High number of deleted files: 4663
        * Changes to user rights assignments: 4704, 4717
        * Altered Audit and Account policies: 4719, 4739
        * Security log cleared: 1102 
        * Reboot: 1074
        * SIDs filtered: 4675
        * New domain trust: 4706
* Resources
    * [Detecting a Security Threat in Event Logs](https://blog.netwrix.com/2014/12/03/detecting-a-security-threat-in-event-logs/)
    * [Windows Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j)
    * [Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
    * [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
    * [Windows security auditing — Event Log FAQ](https://eventlogxp.com/essentials/securityauditing.html)
    * [Windows Security Event Logs: my own cheatsheet](https://andreafortuna.org/2019/06/12/windows-security-event-logs-my-own-cheatsheet/)
    * [Common Windows IDs for SOC](https://www.socinvestigation.com/most-common-windows-event-ids-to-hunt-mind-map/)
    * [MyEventLog](https://www.myeventlog.com/)
    * [Github Eventlog Database](https://github.com/stuhli/awesome-event-ids#event-id-databases)

## Linux Log Analysis
* Description: keywords to search for in linux logs for log analysis
* Usage: `sudo grep -r "search_keyword" /var/log *`
* Search Keywords
    * Successful User Login
        * “Accepted password”, “Accepted publickey”, "session opened”
    * Failed User Login
        * “authentication failure”, “failed password”
    * User Logoff
        * “session closed”
    * User account change or deletion
        * “password changed”, “new user”, “delete user”
    * Sudo Actions
        * “sudo: … COMMAND=…”“FAILED su”
    * Service Failure
        * “failed” or “failure”
* Resources
    * [Searching Log Files](https://www.jungledisk.com/blog/2018/02/15/learning-linux-searching-log-files/)
    * [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)

## Web Server Log Analysis
* Description: list of items to consider for web server forensic analysis
* What to scrutinize
    * Excessive access attempts to non-existent files
    * Code (SQL, HTML) seen as part of the URL
    * Access to extensions you have not implemented
    * Web service stopped/started/failed messages
    * Access to “risky” pages that accept user input
    * Look at logs on all servers in the load balancer pool
    * HTTP Error Codes
        * Error code 200 on files that are not yours
        * Failed user authentication: Error code 401, 403
        * Invalid request: Error code 400
        * Internal server error: Error code 500
* Resources
    * [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)

## Network Device Log Analysis
* Description: list of items to consider for network device forensic analysis
* What to scrutinize
    * Look at both inbound and outbound activities.
* Examples below show log excerpts from Cisco ASA logs; other devices have similar functionality:
    * Traffic allowed on firewall: “Built … connection”, “access-list … permitted”
    * Traffic blocked on firewall: “access-list … denied”, “deny inbound”, “Deny … by”
    * Bytes transferred (large files?): “Teardown TCP connection … duration … bytes …”
    * Bandwidth and protocol usage: “limit … exceeded”, “CPU utilization”
    * Detected attack activity: “attack from”
    * User account changes: “user added”, “user deleted”, “User priv level changed”
    * Administrator access: “AAA user …”, “User … locked out”, “login failed”
* Resources
    * [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)

## Syslog
* Description: standard protocol used to convey event or system log notification messages to a designated server, known as a Syslog server
    * Syslog protocol can be enabled on most network devices
    * Uses UDP 514 by default, TCP 514 for more reliability, TCP 6514 for stricter security standards
* Syslog messages made of three components:
    * Priority Value (PRI): consists of Facility Code and Severity Level tables
    * Header: contains identifying information, such as; Timestamp, Hostname, Application name, Message ID
    * Message: usually saved in a file in /var/log
* Resources
    * [How Does Syslog Work](https://www.auvik.com/franklyit/blog/what-is-syslog/)

## Sysmon
* Description: Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log
* Installation: download from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
* Usage: change to downloaded directory, run sysmon -i as admin in command prompt, sysmon logs sent to Windows Event Viewer
* Resources
    * [Sysmon Configuration File](https://github.com/SwiftOnSecurity/sysmon-config)
    * [Install and use Sysmon for malware investigation](https://support.sophos.com/support/s/article/KB-000038882?language=en_US)

## Splunk
* Description: SIEM with advanced functionality
* Installation: download from https://www.splunk.com/en_us/products/splunk-enterprise.html 
* Usage
    * Starting Splunk on Linux
        * If not a service: `sudo /opt/splunk/bin/splunk start`
        * If running as a service: `sudo systemctl start Splunkd`
    Basic Search Queries
        * Search source IP field (src) and the IP address value 10.10.10.50: `search src="10.10.10.50"`
        * Search desttination IP field (dst): `search dst="10.10.100.5"`    
        * Search source IP field (src) and destination IP field (dst) the IP address value 10.10.10.50: `search src="10.10.10.50" OR dst="10.10.10.50"`
        * Search source IP field (src) to any destination IP field (dst) on the 10.10.10.0/24: `search src="10.10.10.73" dst="10.10.10.*"`
        * Simple failed login failure search: `search pass* AND fail*`
        * Show executables denerated from process, in this case cmd.exe, from Sysmon logs: `index="botsv1" earliest=0 Image="*\\cmd.exe" | stats values(CommandLine) by host`
        * Search for newly created windows user: search eventID field for 4270 or "net user"
        * Search for windows user logins: search eventID field for 4624
        * To search for web scanners: `index=index_name sourcetype=stream:http src_ip=xxx.xxx.xxx.xxx | stats count by src_headers | sort -count | head 3 `
        * Search for .exe: `index=botsv1 sourcetype=stream:http dest_ip="xxx.xxx.xxx.xxx" *.exe`
        * Search for credentials submitted to form:
            ```
            index=botsv1 sourcetype=stream:http dest_ip="xxx.xxx.xxx.xxx" http_method=POST form_data=*username*passwd* 
            | rex field=form_data "passwd=(?<creds>\w+)" 
            |table _time src_ip uri http_user_agent creds
            ```
    * For more detailed usage see: https://github.com/EvolvingSysadmin/Splunk-Tools
* Resources
    * [Splunk Guide](https://github.com/EvolvingSysadmin/Splunk-Tools)
    * [Basic Splunk Searches](https://docs.splunk.com/Documentation/Splunk/9.0.1/SearchTutorial/Startsearching)
    * [Install Splunk on Linux](https://docs.splunk.com/Documentation/SplunkLight/7.3.6/Installation/InstallonLinux)
    * [Install Splunk on Linux – Complete Setup Guide](https://www.inmotionhosting.com/support/security/install-splunk/)
    * [How to install Splunk on an Ubuntu desktop VM (Virtual Box)](https://www.youtube.com/watch?v=TW4l7X6G6Ak)
    * [Splunk Automatically Start upon Boot](https://docs.splunk.com/Documentation/Splunk/9.0.1/Admin/ConfigureSplunktostartatboottime)
    * [Splunk Basic Search Video](https://www.youtube.com/watch?v=xtyH_6iMxwA)

## DeepBlueCLI
* Description: PowerShell Module for Threat Hunting via Windows Event Log
* Installation: download from https://github.com/sans-blue-team/DeepBlueCLI
    * May have to bypass remote code executioin on system: `Set-ExecutionPolicy Bypass -Scope CurrentUser`
* Usage
    * Process local Windows security event log (PowerShell must be run as Administrator): `.\DeepBlue.ps1` or `.\DeepBlue.ps1 -log security`
    * Process local Windows system event log: `.\DeepBlue.ps1 -log system`
    * Process evtx File: `.\DeepBlue.ps1 .\evtx\new-user-security.evtx`
    * Process all logs and output to txt: `./DeepBlue.ps1 .\evtx\* > output.txt`
* Resources
    * [DeepBlueCLI Repo](https://github.com/sans-blue-team/DeepBlueCLI)
    * [DeepBlieCLI Guide](https://www.socinvestigation.com/deepbluecli-powershell-module-for-threat-hunting/)

## Sysinternals
* Description: suite of tools for analyzing Windows systems
* Installation: download from https://learn.microsoft.com/en-us/sysinternals/downloads/
    * Also an online version available: https://live.sysinternals.com/
* Usage
    * Process Monitor: check for suspicious or unknown processes, can be usaed with netstat to track malware
    * Rootkit Revealer: detect rootkits or malware
* Resources
    * [Microsoft Sysinternals site](https://learn.microsoft.com/en-us/sysinternals/)
    * [Process Monitor for Identifying Malware](https://www.techrepublic.com/article/how-to-track-down-malware-from-your-firewall-with-basic-tools/)
    * [RootkitRevealer]https://learn.microsoft.com/en-us/sysinternals/downloads/rootkit-revealer

## SIFT Workstation
* Description: collection of free and open-source incident response and forensic tools designed to perform detailed digital forensic examinations 
* Installation: download from https://github.com/teamdfir/sift-cli#installation for installation on Ubuntu follow: https://www.youtube.com/watch?v=lxLXTdLqgas 
* Usage
* Resources
    * [SANS SIFT Workstation Site](https://www.sans.org/tools/sift-workstation/)
    * [SIFT Workstation Github Repo](https://github.com/teamdfir/sift-cli#installation)
    * [Alternate Ubuntu Installation Guide](https://www.youtube.com/watch?v=jAuWnxt-KqY)

## Other Tools
* Bulk Extractor
* COFEE
* Computer Aided Investigative Environment (CAINE)
* Digital Forensics Framework
* DumpZilla
* Encase
* MAGNET RAM Capture
* Nagios
* Redline
* GitTools
* Nuclei
* https://linuxhint.com/kali_linux_top_forensic_tools/


TODO:
- Install/try phishtool and all other tools
- Install sift workstation
- Install MISP
- Create repository with windows tools and script for installing linux tools