# Sysinternals

Microsoft suite of tools for troubleshooting and analyzing Windows systems.

## When I Use It

* Live analysis of a suspicious Windows host, especially one without EDR
* Reviewing every autostart location on a host for persistence
* Watching what a suspicious program does in a lab VM

## Installation

* Download the suite from <https://learn.microsoft.com/en-us/sysinternals/downloads/>
* Or run tools directly from <https://live.sysinternals.com/> without installing

## Common Tasks

| Tool | Use |
| :--- | :--- |
| Process Explorer | Process tree with command lines, loaded DLLs, handles, signatures, and VirusTotal lookups |
| Process Monitor | Real-time file system, registry, process, and network activity |
| Autoruns | Every autostart location: Run keys, services, scheduled tasks, drivers, WMI, and more |
| TCPView | Network connections mapped to processes |
| Sigcheck | File version, signature, and hash details, with optional VirusTotal checks |
| Strings | Readable strings from binaries: `strings -a file.exe > strings.txt` |
| ProcDump | Dump process memory: `procdump.exe -ma <PID>` |
| Sysmon | Detailed event logging; see [Sysmon](../../siem-and-log-analysis/sysmon.md) |

## Reading the Output

* In Autoruns, Options -> Hide Microsoft Entries and Options -> Scan Options -> Check VirusTotal.com leave a short list of third-party and unknown entries to review
* In Process Explorer, unsigned processes, processes running from user folders, and unusual parents are the first to check
* Process Monitor captures a lot; set filters (process name, operation) before capturing, not after

## Related

* [Windows Artifacts](../windows-artifacts.md)
* [Persistence](../../playbooks/threat-hunting/persistence.md) hunt
* [Endpoint Malware](../../playbooks/incident-response/endpoint-malware.md) playbook

## Resources

* [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/)
* [Process Monitor for Identifying Malware](https://www.techrepublic.com/article/how-to-track-down-malware-from-your-firewall-with-basic-tools/)
