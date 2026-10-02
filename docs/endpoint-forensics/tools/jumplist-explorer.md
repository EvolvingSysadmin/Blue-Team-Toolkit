# JumpList Explorer

Eric Zimmerman tool for parsing Windows jump lists, which record recently and frequently opened files for each application.

## When I Use It

* Showing which files a user opened, and with which application, including files on USB drives and network shares
* Confirming file access when the files themselves have been deleted

## Installation

* Download from <https://ericzimmerman.github.io/>
* Command line version: JLECmd, from the same site

## Common Tasks

| Task | How |
| :--- | :--- |
| Load jump lists in the GUI | File -> Load Jump Lists -> select the files or folder |
| Parse a folder to CSV | `JLECmd.exe -d "<jump list directory>" --csv <output directory>` |

Jump list locations:

* `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`
* `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations`

## Reading the Output

* Each jump list file belongs to one application, identified by the AppID in the file name
* Entries include the target path, volume information, and timestamps, so they show files opened from removable media and network paths

## Related

* [Windows Artifacts](../windows-artifacts.md)
* [KAPE](kape.md), which collects and parses jump lists in bulk

## Resources

* [JLECmd GitHub Repo](https://github.com/EricZimmerman/JLECmd)
* [SANS JumpList Explorer](https://www.sans.org/tools/jumplist-explorer/)
