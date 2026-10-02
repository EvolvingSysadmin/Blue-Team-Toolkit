# John the Ripper

* Description: password hash cracker; used in investigations to recover passwords from hashes and protected files (for example with the `zip2john` and `office2john` helpers), and to test password strength
* Installation: `sudo apt install john` (the "jumbo" build bundled with Kali supports more hash formats and the `*2john` helpers)
* Usage
  * Obtain Linux password hashes from shadow file: `cat /etc/shadow`
  * To combine passwd and shadow files: `unshadow passwd shadow > HashFile`
  * Run against HashFile with the rockyou.txt wordlist: `john HashFile --wordlist=rockyou.txt`
  * Show cracked passwords: `john --show HashFile`
* Resources
  * [John the Ripper Usage Examples](https://www.openwall.com/john/doc/EXAMPLES.shtml)
  * [John the Ripper Tutorial](https://www.varonis.com/blog/john-the-ripper)
  * [Additional Downloads for different Operating Systems](https://www.openwall.com/john/)
  * [Word Lists](https://www.openwall.com/passwords/wordlists/)
  * [Rock You Word List](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
