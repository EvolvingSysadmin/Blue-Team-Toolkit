# John the Ripper

Password hash cracker.

## When I Use It

* Recovering the password to an encrypted file found during an investigation, such as a password-protected ZIP or Office document
* Testing how quickly hashes from an exposed system could be cracked, to judge the impact of a credential leak
* Password auditing, with authorization

## Installation

* Debian / Ubuntu: `sudo apt install john`
* The "jumbo" build (included in Kali, or from <https://www.openwall.com/john/>) supports more hash formats and includes the `*2john` helper tools

## Common Tasks

| Task | Command |
| :--- | :--- |
| Combine Linux passwd and shadow files | `unshadow passwd shadow > hashes.txt` |
| Crack with a wordlist | `john hashes.txt --wordlist=rockyou.txt` |
| Show cracked passwords | `john --show hashes.txt` |
| Extract a hash from a ZIP file | `zip2john protected.zip > zip.hash` |
| Extract a hash from an Office file | `office2john protected.docx > office.hash` |
| Specify the hash format | `john --format=sha512crypt hashes.txt` |

## Reading the Output

* Cracked passwords are stored in the `john.pot` file; `--show` reads them from there
* A password that cracks in seconds from a common wordlist is a finding in its own right

!!! warning "Authorization required"
    Only crack hashes you are authorized to test. Cracked passwords from an investigation are sensitive evidence and need the same handling as the hashes.

## Related

* [Linux Artifacts](../linux-artifacts.md)
* [MITRE ATT&CK: Credential Access](../../threat-intelligence/mitre-attack.md#credential-access)

## Resources

* [John the Ripper Usage Examples](https://www.openwall.com/john/doc/EXAMPLES.shtml)
* [John the Ripper Tutorial](https://www.varonis.com/blog/john-the-ripper)
* [Openwall Wordlists](https://www.openwall.com/passwords/wordlists/)
