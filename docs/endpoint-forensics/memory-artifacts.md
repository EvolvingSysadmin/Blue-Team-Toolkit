# Memory Artifacts

Capturing system memory and the on-disk files that hold memory contents.

## Why It Matters

Memory holds evidence that may never touch disk: injected code, decrypted payloads, command lines, network connections, and sometimes credentials or encryption keys. It is the most volatile evidence on a system and is gone at power off.

## Reference

### Capture Tools

| Platform | Tools |
| :--- | :--- |
| Windows | [FTK Imager](tools/ftk-imager.md) (File -> Capture Memory), Magnet RAM Capture, WinPmem, EDR live response |
| Linux | LiME, AVML |

Captures are analyzed with [Volatility](tools/volatility.md).

### Memory Files on Disk

| File | Location | Contents |
| :--- | :--- | :--- |
| Pagefile | `C:\pagefile.sys` | Memory pages Windows moved out of RAM; can contain fragments of process memory |
| Hibernation file | `C:\hiberfil.sys` | The contents of memory when the system hibernated; can be converted and analyzed like a memory image |
| Swap | Swap partition or `/swapfile` | Linux equivalent of the pagefile |

| Task | Command |
| :--- | :--- |
| Show hidden files on the Windows system drive | `dir /a:h C:\` |
| Show Linux swap usage | `free -h` |
| Show whether Linux swap is a file or a partition | `swapon --show` |

!!! warning "Capture memory before isolating or shutting down"
    Shutting down destroys memory, and some isolation and restart actions change it. If memory might matter, capture it first.

## How I Use It

I capture memory when I suspect fileless malware, process injection, or hands-on-keyboard activity, or when the EDR telemetry for the host is thin. For commodity malware caught at execution with a clear EDR timeline, I usually skip it. The capture goes to external storage or a network share, never the local disk of the system under investigation.

## Related

* [Volatility](tools/volatility.md)
* [Evidence Handling](evidence-handling.md)
* [Endpoint Malware](../playbooks/incident-response/endpoint-malware.md) playbook
