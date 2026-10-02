# ExifTool

Command line tool for reading and writing file metadata (EXIF, XMP, IPTC, and many more formats).

## When I Use It

* Checking documents and images for author names, software versions, creation dates, and GPS coordinates
* Looking for strings hidden in metadata fields during CTF-style challenges and suspicious file analysis
* Confirming a file's real type when the extension may be wrong

## Installation

* Debian / Ubuntu: `sudo apt install libimage-exiftool-perl`
* Windows and macOS: download from <https://exiftool.org/>

## Common Tasks

| Task | Command |
| :--- | :--- |
| Show all metadata | `exiftool file.jpg` |
| Show all files in a folder, recursively | `exiftool -r <directory>` |
| Show specific tags | `exiftool -Author -Creator -CreateDate file.docx` |
| Show GPS coordinates | `exiftool -gps:all file.jpg` |
| Export to CSV | `exiftool -csv -r <directory> > metadata.csv` |
| Write a comment | `exiftool -Comment="sneaky!" dog.jpg` |
| Remove all metadata | `exiftool -all= file.jpg` |

When ExifTool writes a change, it keeps the original file as `<name>_original` (for example `dog.jpg_original`).

## Reading the Output

* `File Type` comes from the file's content, not its extension, so a mismatch is worth a look
* Document metadata often includes the author's account name and the company name set in Office
* Timestamps in metadata are set by the creating software and can be edited; treat them as claims to corroborate

## Related

* [File Metadata](../file-metadata.md)
* [Steghide](steghide.md)
* [Wireshark](../../network-analysis/wireshark.md), for files extracted from captures

## Resources

* [ExifTool Documentation](https://exiftool.org/exiftool_pod.html)
* [ExifTool FAQ](https://exiftool.org/faq.html)
