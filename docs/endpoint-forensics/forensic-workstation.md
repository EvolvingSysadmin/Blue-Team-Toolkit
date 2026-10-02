# Forensic Workstation

A dedicated environment for analyzing evidence and malware samples.

## Why It Matters

Analyzing evidence on an everyday workstation risks contaminating the evidence, infecting the workstation, and exposing case data. A separate, consistent analysis environment avoids all three and means the tools are ready when they are needed.

## Reference

| Setup | Contents |
| :--- | :--- |
| Windows analysis VM | Eric Zimmerman's tools, FTK Imager, Autopsy, KAPE, Sysinternals |
| Linux analysis VM | The [SIFT Workstation](tools/sift-workstation.md) toolset, Volatility, YARA |
| Malware analysis VM | Isolated networking (host-only or none), snapshots, no shared folders or clipboard |

Good practices:

* Take a clean snapshot and revert to it before each case
* Keep case data in an encrypted, access-controlled location
* Keep tools and symbol tables updated between cases, not during them

## How I Use It

I keep a Windows VM and a Linux VM ready with the tools on these pages, each with a clean snapshot. Anything that might execute malware runs on a VM with networking disabled, and case data stays off my day-to-day machine.

## Related

* [SIFT Workstation](tools/sift-workstation.md)
* [Evidence Handling](evidence-handling.md)

## Resources

* [Build Your Forensic Workstation (Blue Cape Security)](https://bluecapesecurity.com/build-your-forensic-workstation/)
* [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation/)
* [Eric Zimmerman's Tools](https://ericzimmerman.github.io/)
