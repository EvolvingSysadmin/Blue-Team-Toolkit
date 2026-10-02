# Sysinternals

* Description: Microsoft suite of tools for troubleshooting and analyzing Windows systems
* Installation: download from <https://learn.microsoft.com/en-us/sysinternals/downloads/>
  * Tools can also be run directly from <https://live.sysinternals.com/>
* Tools useful for investigations
  * Process Explorer: detailed process tree with command lines, loaded DLLs, handles, and VirusTotal lookups
  * Process Monitor: real-time file system, registry, process, and network activity; useful for watching what a suspicious program does
  * Autoruns: every autostart location (Run keys, services, scheduled tasks, drivers, WMI); the fastest way to review persistence
  * TCPView: network connections mapped to processes
  * Sigcheck: file version, signature, and hash details; can check files against VirusTotal
  * Strings: extract readable strings from binaries
  * ProcDump: dump process memory for analysis
  * Sysmon: see [Sysmon](../../siem-and-log-analysis/sysmon.md)
* Resources
  * [Microsoft Sysinternals site](https://learn.microsoft.com/en-us/sysinternals/)
  * [Process Monitor for Identifying Malware](https://www.techrepublic.com/article/how-to-track-down-malware-from-your-firewall-with-basic-tools/)
