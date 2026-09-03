# Prefetch Explorer Command Tool PECmd.exe

* Description: used to fetch all possible forensic artifacts from a Windows prefetch file, which can be used to investigate applciations executed on a system
* Installation: download program at <https://ericzimmerman.github.io/#!index.md>
* Usage:
  * On single file: `PECmd.exe -f "C:\tmp\calc.exe-asdfasd.pf"`
  * On directory: `PECmd.exe -d "C:\tmp\pfdirectory\"`
  * To run a string match in a directory: `PECmd.exe -k “plaguerat.ps1” -d "C:\Users\BTLOTest\Desktop\Windows Investigation One\Prefetch\"`
    * Example: `PECmd.exe -k “plaguerat.ps1” -d "C:\Users\BTLOTest\Desktop\Windows Investigation One\Prefetch\"`
* Resources
  * [PECmd.cmd Documentation](https://github.com/EricZimmerman/PECmd)
