# File Hashing

* Use SHA256 for evidence integrity and threat intel lookups; MD5 and SHA1 have known collisions but are still used by older tools and indicator feeds
* Linux
  * Hash a text string: `echo -n 'This is the text' | sha256sum`
  * Hash a file
    * `sha256sum <file>`
    * `sha1sum <file>`
    * `md5sum <file>`
    * Example: `sha256sum hashthis.jpg && sha1sum hashthis.jpg && md5sum hashthis.jpg`
  * Verify against a list of hashes: `sha256sum -c hashes.txt`
* Windows
  * PowerShell: `Get-FileHash -Algorithm <algorithm> .\file_path` (SHA256 is the default)
    * Example: `Get-FileHash -Algorithm SHA1 .\hashthis.jpg`
    * Example: `Get-FileHash .\file.exe; Get-FileHash -Algorithm MD5 .\file.exe; Get-FileHash -Algorithm SHA1 .\file.exe`
  * Command prompt: `certutil -hashfile file.exe SHA256`
