# Volatility

* Description: memory forensics framework for analyzing RAM captures. Capabilities include:
  * Listing running and terminated processes, including hidden ones
  * Process command lines, loaded DLLs, and handles
  * Active and closed network connections
  * Finding injected code
  * Listing and extracting files and process executables from memory
  * Registry hives and keys loaded in memory
  * Password hashes and cached domain credentials
  * Scanning memory with YARA rules
* Volatility 3 is the current version (Python 3). Volatility 2 (Python 2, profile-based) is no longer maintained, but older training material and writeups still use it; see the comparison below
* Installation
  * `pip install volatility3` (provides the `vol` command)
  * Or clone the repo: `git clone https://github.com/volatilityfoundation/volatility3.git` then run `python3 vol.py`
  * Windows symbol tables are downloaded automatically on first use (internet access required) or can be installed offline from the symbol packs; Linux and macOS images need a matching symbol table (ISF)
* Usage (Volatility 3, Windows image)
  * `vol -f memdump.mem windows.info`: OS version and build of the image
  * `vol -f memdump.mem windows.pslist`: list processes
  * `vol -f memdump.mem windows.pstree`: process tree (parent-child relationships)
  * `vol -f memdump.mem windows.psscan`: scan for process structures, including terminated and unlinked (hidden) processes
  * `vol -f memdump.mem windows.cmdline`: command line arguments for each process
  * `vol -f memdump.mem windows.dlllist --pid 2352`: DLLs loaded by process 2352
  * `vol -f memdump.mem windows.netscan`: active and closed network connections
  * `vol -f memdump.mem windows.malfind`: memory regions that may contain injected code
  * `vol -f memdump.mem windows.svcscan`: services
  * `vol -f memdump.mem windows.filescan`: file objects in memory
  * `vol -f memdump.mem -o ./out windows.dumpfiles --pid 2940`: extract files associated with a process
  * `vol -f memdump.mem -o ./out windows.pslist --pid 2940 --dump`: dump the executable for process 2940
  * `vol -f memdump.mem windows.hashdump`: local account password hashes from the SAM
  * `vol -f memdump.mem windows.cachedump`: cached domain credentials
  * `vol -f memdump.mem windows.registry.hivelist`: registry hives in memory
  * `vol -f memdump.mem timeliner.Timeliner`: timeline of events from all supported plugins
  * `vol -f memdump.mem yarascan.YaraScan --yara-file rules.yar`: scan memory with YARA rules
* Examples
  * Find svchost processes: `vol -f memdump1.mem windows.pslist | grep -i "svchost.exe"`
  * Count svchost processes: `vol -f memdump1.mem windows.pslist | grep -ic "svchost.exe"`
  * Find PowerShell or cmd processes in the tree: `vol -f memdump1.mem windows.pstree | grep -i "powershell\|cmd"`
* Volatility 2 Comparison
  * Volatility 2 needs a profile for every command: identify it with `imageinfo`, then pass it with `--profile=Win7SP1x64`
  * Command format: `python vol.py -f memdump.mem --profile=Win7SP1x64 pslist`
  * Plugin names map closely: `pslist` -> `windows.pslist`, `netscan` -> `windows.netscan`, `procdump` -> `windows.pslist --dump`, `imageinfo` -> `windows.info`
  * Some Volatility 2 plugins, such as `iehistory`, `notepad`, `screenshot`, and `clipboard`, have no direct Volatility 3 equivalent
* Resources
  * [Volatility 3 Documentation](https://volatility3.readthedocs.io/en/latest/)
  * [Volatility 3 GitHub](https://github.com/volatilityfoundation/volatility3)
  * [Volatility Foundation](https://volatilityfoundation.org/)
  * [Memory Samples for Test Analysis](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)
  * [Volatility 2 Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
  * [Volatility 3 vs Volatility 2 Cheat Sheet](https://blog.onfvp.com/post/volatility-cheatsheet/)
  * [Volatility Examples (HackTricks)](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-examples)
