# File Metadata

Timestamps, properties, and embedded metadata that show where a file came from and what happened to it.

## Why It Matters

Metadata answers questions the file contents do not: when a file was created or changed, who authored it, what software produced it, where a photo was taken, and whether a file was downloaded from the internet.

## Reference

### Viewing Metadata

| Task | Windows | Linux |
| :--- | :--- | :--- |
| Basic properties and timestamps | Right click -> Properties -> Details, or `Get-ChildItem .\file.jpg | Format-List *` | `stat <file>` |
| Detailed listing | `Get-Item .\file.jpg | Select-Object *` | `ls -lisap <file>` |
| Mark of the Web on a downloaded file | `Get-Content .\file.exe -Stream Zone.Identifier` | |
| Embedded metadata (author, software, GPS) | [ExifTool](tools/exiftool.md) | [ExifTool](tools/exiftool.md) |

### Zone.Identifier Values

| ZoneId | Zone |
| :--- | :--- |
| 0 | Local computer |
| 1 | Local intranet |
| 2 | Trusted sites |
| 3 | Internet |
| 4 | Restricted sites |

The stream can also record the `ReferrerUrl` and `HostUrl`, which show where a file was downloaded from.

## How I Use It

For a suspicious file, I check the Zone.Identifier stream first: it shows whether the file came from the internet and often the exact URL. Then I run ExifTool for embedded metadata, which on documents can reveal the author name, the software used, and creation dates that do not match the story the file is telling.

## Related

* [ExifTool](tools/exiftool.md)
* [File Systems](file-systems.md)
* [Windows Artifacts](windows-artifacts.md)

## Resources

* [PowerShell Get-FileMetaData function](https://gist.github.com/woehrl01/5f50cb311f3ec711f6c776b2cb09c34e)
