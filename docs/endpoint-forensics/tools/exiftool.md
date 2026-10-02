# Exiftool

* Description: used to get file metadata, can be used to extract strings from metadata
* Linux Installation: `sudo apt-get install exiftool`
* Windows Installation: download from <https://exiftool.org/>
* Usage
  * To retrieve file metadata: `exiftool <filename>`
  * To embed "sneaky!" into dpg.jpg: `exiftool -Comment="sneaky!" dog.jpg` -> this creates file with embedded text called `dog.jpg_original`
* Resources
  * [ExifTool FAQ](https://exiftool.org/faq.html)
  * [Exiftool Installation](https://exiftool.org/install.html)
  * [Exiftool Linux Man Page](https://linux.die.net/man/1/exiftool)
  * [Online Exiftool](https://exif.tools/)
  * [Another Online Exiftool](http://exif-viewer.com/)
  * [Exporting DData from TCP Stream](https://medium.com/@sshekhar01/cyberdefenders-packetmaze-beffc1d05cb)
  