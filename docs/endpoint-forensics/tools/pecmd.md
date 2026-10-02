# PECmd

* Description: Eric Zimmerman's Prefetch Explorer Command Line tool; parses Windows prefetch files to show which applications ran, how many times, when, and what files they loaded
* Installation: download from <https://ericzimmerman.github.io/>
* Usage
  * Single file: `PECmd.exe -f "C:\Windows\Prefetch\CALC.EXE-3FBEF7FD.pf"`
  * Directory: `PECmd.exe -d "C:\Windows\Prefetch"`
  * Directory with CSV output for Timeline Explorer: `PECmd.exe -d "C:\Windows\Prefetch" --csv C:\cases\output`
  * Highlight a keyword in a directory: `PECmd.exe -k "plaguerat.ps1" -d "C:\cases\Prefetch"`
* Resources
  * [PECmd GitHub Repo](https://github.com/EricZimmerman/PECmd)
