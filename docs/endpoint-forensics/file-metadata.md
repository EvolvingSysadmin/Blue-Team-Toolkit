# File Metadata

* Windows
  * Right click file -> Properties -> Details
  * PowerShell: `Get-ChildItem .\path-to-file.jpg | Format-List *`
  * PowerShell Get-FileMetaData function: <https://gist.github.com/woehrl01/5f50cb311f3ec711f6c776b2cb09c34e>
  * Check for a Mark of the Web stream on a downloaded file: `Get-Content .\file.exe -Stream Zone.Identifier`
* Linux
  * `ls -lisap <file>`
  * `stat <file>`
* Embedded metadata (author, camera, GPS, software): [ExifTool](tools/exiftool.md)
