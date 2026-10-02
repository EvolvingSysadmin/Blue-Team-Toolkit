# John the Ripper

* Description: used to crack password hashes, including passwords from the passwd and shadow files in Linux
* Installation: `sudo apt-get install john`
* Usage
  * Obtain Linux password hashes from shadow file: `cat /etc/shadow`
  * To combine passwd and shadow files: `unshadow passwd shadow > HashFile`
  * To run using HashFile as input and rockyou.txt as word list with both files in current directory: `john HashFile --wordlist=rockyou.txt`
* Resources
  * [John the Ripper Usage Examples](https://www.openwall.com/john/doc/EXAMPLES.shtml)
  * [John the Ripper Tutorial](https://www.varonis.com/blog/john-the-ripper)
  * [Additional Downloads for different Operating Systems](https://www.openwall.com/john/)
  * [Word Lists](https://www.openwall.com/passwords/wordlists/)
  * [Rock You Word List](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
