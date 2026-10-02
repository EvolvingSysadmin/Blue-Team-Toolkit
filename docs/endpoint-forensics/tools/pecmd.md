# PECmd

Eric Zimmerman's Prefetch Explorer command line tool for parsing Windows prefetch files.

## When I Use It

* Proving a program ran on a system, and when, even if the program has since been deleted
* Finding attacker tools by name or by the files they loaded
* Building an execution timeline across all prefetch files on a host

## Installation

* Download from <https://ericzimmerman.github.io/>

## Common Tasks

| Task | Command |
| :--- | :--- |
| Parse one file | `PECmd.exe -f "C:\Windows\Prefetch\CALC.EXE-3FBEF7FD.pf"` |
| Parse a directory | `PECmd.exe -d "C:\Windows\Prefetch"` |
| Parse a directory to CSV | `PECmd.exe -d "C:\Windows\Prefetch" --csv C:\cases\output` |
| Highlight a keyword | `PECmd.exe -k "plaguerat.ps1" -d "C:\cases\Prefetch"` |

## Reading the Output

* **Run count and last run times:** up to eight run times on Windows 8 and later
* **Files and directories referenced:** what the program loaded in its first seconds, which often reveals its working folder and any payloads
* **Volume information:** shows whether the program ran from a USB drive or network share

The CSV output includes a timeline file, which is the easiest view for building an execution timeline.

## Related

* [Windows Artifacts](../windows-artifacts.md)
* [KAPE](kape.md)

## Resources

* [PECmd GitHub Repo](https://github.com/EricZimmerman/PECmd)
