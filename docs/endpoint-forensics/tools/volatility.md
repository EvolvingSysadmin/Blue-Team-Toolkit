# Volatility

Memory forensics framework for analyzing RAM captures from Windows, Linux, and macOS systems.

## When I Use It

* A host may be running fileless malware or injected code that never touches disk
* I need the process tree, command lines, and network connections as they were at the moment of capture, including connections that have already closed
* EDR telemetry is missing or incomplete for the time of the incident
* I need to recover something that only exists in memory: a decrypted payload, a command line, or credentials an attacker could have dumped

Memory has to be captured before the host is powered off or restarted. See [Memory Artifacts](../memory-artifacts.md) for capture tools.

## Installation

* `pip install volatility3`, which provides the `vol` command
* Or clone the repository and run `python3 vol.py`: `git clone https://github.com/volatilityfoundation/volatility3.git`
* Windows symbol tables download automatically on first use, which needs internet access; offline symbol packs are available from the Volatility Foundation. Linux and macOS images need a symbol table (ISF) that matches the exact kernel.

!!! warning "Volatility 3 vs Volatility 2"
    Volatility 3 is the current version. Volatility 2 (Python 2, profile-based) is no longer maintained, but a lot of training material and older writeups still use it. Commands with `--profile=` or `imageinfo` are Volatility 2. See the [comparison](#volatility-2-comparison) below.

## Common Tasks

### Identify the Image

```bash
vol -f memdump.mem windows.info
```

Shows the OS version, build, and capture time. If this fails, the image is damaged, the wrong OS, or missing symbols.

### List Processes

| Command | What It Shows |
| :--- | :--- |
| `vol -f memdump.mem windows.pslist` | Processes from the active process list |
| `vol -f memdump.mem windows.pstree` | The same processes as a parent-child tree |
| `vol -f memdump.mem windows.psscan` | Process structures found by scanning memory, including terminated and unlinked (hidden) processes |
| `vol -f memdump.mem windows.cmdline` | The command line of each process |

### Network Connections

```bash
vol -f memdump.mem windows.netscan
```

Lists TCP and UDP connections and listeners with the owning process, including recently closed connections.

### Find Injected Code

```bash
vol -f memdump.mem windows.malfind
```

Lists memory regions that are executable and writable and not backed by a file on disk, which is typical of injected shellcode or unpacked malware.

### Inspect a Process

| Command | What It Shows |
| :--- | :--- |
| `vol -f memdump.mem windows.dlllist --pid 2352` | DLLs loaded by the process |
| `vol -f memdump.mem windows.handles --pid 2352` | Open handles: files, registry keys, mutexes |
| `vol -f memdump.mem windows.svcscan` | Services and their binaries |

### Extract Files and Executables

```bash
vol -f memdump.mem -o ./out windows.pslist --pid 2940 --dump
vol -f memdump.mem -o ./out windows.dumpfiles --pid 2940
vol -f memdump.mem windows.filescan | grep -i "invoice"
```

The first command dumps the process executable, the second extracts files mapped by the process, and `filescan` finds file objects to extract by offset.

### Credentials and Registry

| Command | What It Shows |
| :--- | :--- |
| `vol -f memdump.mem windows.hashdump` | Local account password hashes from the SAM |
| `vol -f memdump.mem windows.cachedump` | Cached domain credentials |
| `vol -f memdump.mem windows.registry.hivelist` | Registry hives loaded in memory |

### Timeline and YARA

```bash
vol -f memdump.mem timeliner.Timeliner
vol -f memdump.mem yarascan.YaraScan --yara-file rules.yar
```

### Filtering Output

Volatility output is plain text, so `grep` handles most filtering:

```bash
vol -f memdump.mem windows.pslist | grep -i "svchost.exe"
vol -f memdump.mem windows.pslist | grep -ic "svchost.exe"
vol -f memdump.mem windows.pstree | grep -i "powershell\|cmd"
```

`-r csv` or `-r json` produces output for spreadsheets and scripts.

## Reading the Output

* **Compare `pslist` with `psscan`.** A process in `psscan` but not `pslist` either exited before capture or was hidden by unlinking it from the process list. The exit time column tells them apart.
* **Check parent-child relationships in `pstree`.** `svchost.exe` should be a child of `services.exe`; there should be one `lsass.exe`, a child of `wininit.exe`; Office applications and browsers should not be parents of `cmd.exe` or `powershell.exe`.
* **Check paths and names.** Core Windows processes running from outside `C:\Windows\System32`, or names one letter off (`scvhost.exe`, `lsas.exe`), are classic masquerading.
* **`malfind` is noisy.** .NET applications, browsers, and some security tools legitimately create executable memory. Results with an `MZ` header or recognizable shellcode at the start of the region deserve a closer look.
* **Timestamps are UTC.**

## Volatility 2 Comparison

| Volatility 2 | Volatility 3 |
| :--- | :--- |
| `python vol.py -f mem.raw imageinfo` | `vol -f mem.raw windows.info` |
| `--profile=Win7SP1x64 pslist` | `windows.pslist` (no profile needed) |
| `netscan` | `windows.netscan` |
| `procdump -p 2940 -D ./out` | `-o ./out windows.pslist --pid 2940 --dump` |
| `iehistory`, `notepad`, `screenshot`, `clipboard` | No direct equivalent |

## Related

* [Endpoint Malware](../../playbooks/incident-response/endpoint-malware.md) playbook
* [Ransomware](../../playbooks/incident-response/ransomware.md) playbook
* [Memory Artifacts](../memory-artifacts.md)
* [YARA](../../malware-analysis/yara.md)

## Resources

* [Volatility 3 Documentation](https://volatility3.readthedocs.io/en/latest/)
* [Volatility 3 GitHub](https://github.com/volatilityfoundation/volatility3)
* [Volatility Foundation](https://volatilityfoundation.org/)
* [Memory Samples for Practice](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)
* [Volatility 3 vs Volatility 2 Cheat Sheet](https://blog.onfvp.com/post/volatility-cheatsheet/)
