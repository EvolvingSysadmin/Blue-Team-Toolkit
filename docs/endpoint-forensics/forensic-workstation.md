# Forensic Workstation

* A dedicated analysis system keeps evidence and malware samples away from production systems
* Common setups
  * Windows VM with Eric Zimmerman's tools, FTK Imager, Autopsy, KAPE, and Sysinternals
  * Linux VM with the [SIFT Workstation](tools/sift-workstation.md) toolset
  * Isolated networking (host-only or no network) when handling live malware
  * Snapshots taken before each case so the VM can be reset
* Resources
  * [Build Your Forensic Workstation (Blue Cape Security)](https://bluecapesecurity.com/build-your-forensic-workstation/)
  * [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation/)
  * [Eric Zimmerman's Tools](https://ericzimmerman.github.io/)
