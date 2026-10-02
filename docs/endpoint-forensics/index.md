# Endpoint Forensics

Collecting and analyzing evidence from Windows and Linux systems: what to collect, where it lives, and the tools that parse it.

## Reference Pages

| Page | Description |
| :--- | :--- |
| [Evidence Handling](evidence-handling.md) | Order of volatility, integrity, and chain of custody |
| [Forensic Workstation](forensic-workstation.md) | Setting up an analysis environment |
| [File Systems](file-systems.md) | FAT, exFAT, NTFS, and EXT, and the structures useful in investigations |
| [File Metadata](file-metadata.md) | Timestamps, properties, and embedded metadata |
| [File Hashing](file-hashing.md) | Hashing for integrity and threat intel lookups |
| [Windows Artifacts](windows-artifacts.md) | Prefetch, LNK files, jump lists, Recycle Bin, and live response commands |
| [Linux Artifacts](linux-artifacts.md) | Accounts, logs, history, and persistence locations |
| [Memory Artifacts](memory-artifacts.md) | Memory capture, pagefile, swap, and hibernation files |

## Tools

| Category | Tools |
| :--- | :--- |
| Acquisition and triage | [FTK Imager](tools/ftk-imager.md), [KAPE](tools/kape.md) |
| Analysis platforms | [Autopsy](tools/autopsy.md), [SIFT Workstation](tools/sift-workstation.md) |
| Memory | [Volatility](tools/volatility.md) |
| Windows artifacts | [PECmd](tools/pecmd.md), [JumpList Explorer](tools/jumplist-explorer.md), [Windows File Analyzer](tools/windows-file-analyzer.md), [Sysinternals](tools/sysinternals.md) |
| Browser | [Browser History Capturer](tools/browser-history-capturer.md), [Browser History Viewer](tools/browser-history-viewer.md) |
| Files and data recovery | [ExifTool](tools/exiftool.md), [Scalpel](tools/scalpel.md), [Steghide](tools/steghide.md), [John the Ripper](tools/john-the-ripper.md) |
| Other | [Other Tools](tools/other-tools.md) |

## Related

* [Endpoint Malware](../playbooks/incident-response/endpoint-malware.md) playbook
* [Ransomware](../playbooks/incident-response/ransomware.md) playbook
