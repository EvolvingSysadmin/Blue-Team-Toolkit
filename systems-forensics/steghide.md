# Steghide

* Description: used to hide and retrieve files, files can be easily hidden using steganography by running something like `cat Dog.jpg secretmessage.zip > Dog2.jpg` which hides the zip inside the jpg file
* Installation: `sudo apt-get install steghide`
* Usage
  * To hide secretmessage.txt inside dog.jpg: `steghide embed -cf dog.jpg -ef secretmessage.txt`
    * `embed`: specifies operation
    * `-cf dog.jpg`: cover file using dog.jpg
    * `-ef secretmessage.txt`: embedded file using secretmessage.txt
  * To extract hidden file: `steghide extract -sf dog.jpg`
    * `extract`: specifies operation
    * `-sf dog.jpg`: steganogrphy flag to specify file with potentially hidden data
* Resources
  * [Steghide Website](https://steghide.sourceforge.net/)
  * [Steghide Download](https://steghide.sourceforge.net/download.php)
  * [Steghide Manual](https://steghide.sourceforge.net/documentation/manpage.php)
  * [Steghide Tutorial](https://linuxhint.com/steghide-beginners-tutorial/)
