# File Hashing

* Linux
  * Get hash of text string: `echo -n 'This is the text' | md5sum`
    * Example: `echo -n "This is the text" | md5sum`
  * Get hash of file
    * `sha256sum <file>`
    * `sha1sum <file>`
    * `md5sum <file>`
    * Examples
      * `sha256sum hashthis.jpg`
      * `sha256sum hashthis.jpg && sha1sum hashthis.jpg && md5sum hashthis.jpg`
* Windows
  * `Get-FileHash -Algorithm <algorithm> .\file_path`
    * Examples
      * `Get-FileHash -Algorithm sha1 .\hashthis.jpg`
      * `get-filehash .\file.exe ; get-filehash -algorithm md5 .\file.exe ; get-filehash -algorithm sha1 .\file.exe`
