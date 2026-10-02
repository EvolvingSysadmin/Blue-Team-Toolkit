# Memory Artifacts

* Memory capture
  * Capture memory before shutting a system down; memory contents are lost at power off
  * Windows tools: [FTK Imager](tools/ftk-imager.md) (File -> Capture Memory), Magnet RAM Capture, WinPmem
  * Linux tools: LiME, AVML
  * Analyze captures with [Volatility](tools/volatility.md)
* Pagefile.sys: Windows stores memory pages here when RAM is full; may contain fragments of process memory
  * Location: `C:\pagefile.sys`
  * Show the hidden file: `dir /a:h C:\`
* Swap: Linux equivalent of the pagefile, stored in a swap partition or swap file
  * Show swap usage: `free -h`
  * Show whether swap is a file or a partition: `swapon --show`
* Hibernation file: Windows writes the contents of memory to `C:\hiberfil.sys` when the system hibernates; it can be converted and analyzed like a memory image
