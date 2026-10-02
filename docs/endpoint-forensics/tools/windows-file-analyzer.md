# Windows File Analyzer

MiTeC tool that decodes Windows files such as LNK (shortcut) files, prefetch files, and index.dat.

## When I Use It

* Quick, GUI-based review of LNK files to see what a user opened
* Older systems and training exercises that use legacy artifacts like index.dat

For current Windows versions, LECmd and PECmd from Eric Zimmerman's tools are maintained and more complete.

## Installation

* Download from <https://www.mitec.cz/wfa.html>

## Common Tasks

| Task | Steps |
| :--- | :--- |
| Analyze shortcuts | File -> Analyze Shortcuts -> select the folder of LNK files |
| Analyze prefetch | File -> Analyze Prefetch -> select the Prefetch folder |

## Reading the Output

LNK analysis shows each shortcut's target path, the target's timestamps, and volume details, which shows files opened from USB drives and network shares.

## Related

* [Windows Artifacts](../windows-artifacts.md)
* [PECmd](pecmd.md)

## Resources

* [Windows File Analyzer background and usage](https://www.portablefreeware.com/index.php?id=2298)
* [Eric Zimmerman's Tools](https://ericzimmerman.github.io/)
