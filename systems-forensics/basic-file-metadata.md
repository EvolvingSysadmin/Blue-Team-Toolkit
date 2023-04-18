# Basic File Metadata

* Windows
  * Right click file -> Properties -> Details
  * PowerShell: `Get-ChildItem .\path-to-file.jpg | Format-List *`
  * PowerShell Get-FileMetaData Function: <https://gist.github.com/woehrl01/5f50cb311f3ec711f6c776b2cb09c34e>
* Linux
  * `ls -lisap <file>`
  * `stat <file>`
