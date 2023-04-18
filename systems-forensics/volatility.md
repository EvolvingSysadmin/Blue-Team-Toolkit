# Volatility

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
  * Can be downloaded and installed from <https://www.volatilityfoundation.org/releases>
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
    * `volatility -f memdump.mem --profile=PROFILE hashdump`: extract and decrypt cached domain credentials stored in the registry
  * Volatility Examples
    * `python vol.py -f /home/ubuntu/Desktop/Volatility\ memdump1.mem imageinfo`: identify memory sample information like system architecture
    * `python vol.py -f /home/ubuntu/Desktop/Volatility\ memdump1.mem --profile=Win7SP1x64 pslist | grep “svchost.exe”`: find processes using volatility and pipe output into grep to search for lines containing "svchost.exe"
    * `python vol.py -f /home/ubuntu/Desktop/Volatility\ memdump1.mem --profile=Win7SP1x64 pslist | grep “svchost.exe” | wc -l`: outputs wordcount of number of ""svchost.exe" services identified by volatility
    * `python vol.py -f /home/ubuntu/Desktop/Volatility\ memdump1.mem --profile=Win7SP1x64 dlllist -p 2352`: find command line arguments used by process 2352
    * `python vol.py -f /home/ubuntu/Desktop/Volatility\ Exercise/memdump2.mem --profile=Win7SP1x64 procdump -p 2940 --dump-dir /path/to/output/directory`: dumps the executable for process 2940 to current directory
    * `python vol.py -f mem_file.raw --profile=SuggestProfile pstree | grep "powershell\|cmd"`
* Resources
  * [Volatility Reference Guide](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
  * [Volatility Downloads](https://www.volatilityfoundation.org/releases)
  * [Volatility Installation](https://github.com/volatilityfoundation/volatility/wiki/Installation)
  * [Volatility Wiki](https://github.com/volatilityfoundation/volatility/wiki)
  * [Volatility Documentation](https://volatility3.readthedocs.io/en/latest/)
  * [Volatility GitHub](https://github.com/volatilityfoundation/volatility/wiki/Installation)
  * [Memory Samples for Test Analysis](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)
  * [Volatility Cheat Sheet](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-examples)
  * [Another Volatility3 v Volatility2 Cheat Sheet](https://blog.onfvp.com/post/volatility-cheatsheet/)
  * [Volatility Tutorial](https://medium.com/@zemelusa/first-steps-to-volatile-memory-analysis-dcbd4d2d56a1)
