# File Hashing

Generating cryptographic hashes for evidence integrity and threat intelligence lookups.

## Why It Matters

A hash identifies a file exactly. It proves evidence has not changed since collection, and it is the fastest way to check a file against threat intelligence or search for the same file across every endpoint.

## Reference

### Algorithms

| Algorithm | Use |
| :--- | :--- |
| SHA256 | Default choice for evidence integrity and threat intel lookups |
| SHA1 | Still used by some tools and indicator feeds; known collisions |
| MD5 | Still common in older tools and feeds; known collisions, not suitable for integrity on its own |

### Commands

| Task | Windows | Linux |
| :--- | :--- | :--- |
| Hash a file (SHA256) | `Get-FileHash .\file.exe` | `sha256sum file` |
| Other algorithms | `Get-FileHash -Algorithm SHA1 .\file.exe` or `-Algorithm MD5` | `sha1sum file`, `md5sum file` |
| Hash from the command prompt | `certutil -hashfile file.exe SHA256` | |
| Hash a text string | | `echo -n 'This is the text' | sha256sum` |
| Hash every file in a folder | `Get-ChildItem -Recurse -File | Get-FileHash` | `find . -type f -exec sha256sum {} +` |
| Verify against a list | | `sha256sum -c hashes.txt` |

## How I Use It

I hash every file I collect at the time of collection and record the hash with the evidence notes. For suspicious files, the SHA256 is the first thing I look up in VirusTotal and the first thing I search across EDR to see where else the file exists.

## Related

* [Evidence Handling](evidence-handling.md)
* [Endpoint Malware](../playbooks/incident-response/endpoint-malware.md) playbook
* [Email Fundamentals](../phishing-and-email/email-fundamentals.md)
