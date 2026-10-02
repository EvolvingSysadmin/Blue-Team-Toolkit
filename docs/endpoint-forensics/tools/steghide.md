# Steghide

* Description: hides data inside JPEG, BMP, WAV, and AU files using steganography, and extracts it with the passphrase
* Installation: `sudo apt install steghide`
* Usage
  * Hide secretmessage.txt inside dog.jpg: `steghide embed -cf dog.jpg -ef secretmessage.txt`
    * `embed`: specifies the operation
    * `-cf dog.jpg`: cover file
    * `-ef secretmessage.txt`: file to embed
  * Check whether a file contains embedded data: `steghide info dog.jpg`
  * Extract a hidden file: `steghide extract -sf dog.jpg`
    * `extract`: specifies the operation
    * `-sf dog.jpg`: stego file that may contain hidden data
* Related techniques
  * Appending a file to another, for example `cat Dog.jpg secretmessage.zip > Dog2.jpg`, hides a zip after the end of the image; the image still opens normally. Detect with `binwalk Dog2.jpg` and extract with `binwalk -e Dog2.jpg`
  * Stegseek can brute force steghide passphrases with a wordlist
* Resources
  * [Steghide Website](https://steghide.sourceforge.net/)
  * [Steghide Manual](https://steghide.sourceforge.net/documentation/manpage.php)
  * [Steghide Tutorial](https://linuxhint.com/steghide-beginners-tutorial/)
  * [Stegseek](https://github.com/RickdeJager/stegseek)
