# ExifTool

* Description: reads and writes file metadata (EXIF, XMP, IPTC, and more); useful for finding authors, software, GPS coordinates, timestamps, and strings hidden in metadata
* Linux installation: `sudo apt install libimage-exiftool-perl`
* Windows installation: download from <https://exiftool.org/>
* Usage
  * Show file metadata: `exiftool <filename>`
  * Show metadata for every file in a directory: `exiftool -r <directory>`
  * Add the comment "sneaky!" to dog.jpg: `exiftool -Comment="sneaky!" dog.jpg`
    * ExifTool writes the change to `dog.jpg` and keeps the unmodified file as `dog.jpg_original`
* Resources
  * [ExifTool FAQ](https://exiftool.org/faq.html)
  * [ExifTool Installation](https://exiftool.org/install.html)
  * [ExifTool Documentation](https://exiftool.org/exiftool_pod.html)
