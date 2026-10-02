# Steghide

Steganography tool that hides data inside JPEG, BMP, WAV, and AU files and extracts it with a passphrase.

## When I Use It

* Checking image and audio files for hidden data during investigations and CTF-style challenges
* Understanding how data can be hidden in ordinary-looking files, for data exfiltration cases

## Installation

* Debian / Ubuntu: `sudo apt install steghide`

## Common Tasks

| Task | Command |
| :--- | :--- |
| Check whether a file contains embedded data | `steghide info dog.jpg` |
| Extract hidden data | `steghide extract -sf dog.jpg` |
| Hide a file | `steghide embed -cf dog.jpg -ef secretmessage.txt` |

| Option | Meaning |
| :--- | :--- |
| `-cf` | Cover file to hide data in |
| `-ef` | File to embed |
| `-sf` | Stego file that may contain hidden data |

### Related Techniques

| Technique | How to Detect |
| :--- | :--- |
| File appended to another, for example `cat Dog.jpg secret.zip > Dog2.jpg`; the image still opens normally | `binwalk Dog2.jpg`; extract with `binwalk -e Dog2.jpg` |
| Unknown steghide passphrase | [Stegseek](https://github.com/RickdeJager/stegseek) brute forces it with a wordlist |
| Data hidden in PNG files | zsteg |

## Reading the Output

* `steghide info` asks for a passphrase; an empty passphrase works surprisingly often
* A file noticeably larger than similar files with the same dimensions is worth checking

## Related

* [ExifTool](exiftool.md)
* [File Metadata](../file-metadata.md)

## Resources

* [Steghide Manual](https://steghide.sourceforge.net/documentation/manpage.php)
* [Steghide Tutorial](https://linuxhint.com/steghide-beginners-tutorial/)
* [Stegseek](https://github.com/RickdeJager/stegseek)
