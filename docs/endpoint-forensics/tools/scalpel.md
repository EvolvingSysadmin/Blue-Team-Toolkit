# Scalpel

File carving tool that recovers deleted files from disk images by searching for known file headers and footers.

## When I Use It

* Recovering deleted files when the file system metadata is gone or damaged
* Finding files with custom signatures, such as challenge files with a known header

Scalpel is no longer actively developed. Foremost and PhotoRec are common alternatives.

## Installation

* Debian / Ubuntu: `sudo apt install scalpel`

## Common Tasks

| Task | How |
| :--- | :--- |
| Choose file types | Uncomment the types to recover in `/etc/scalpel/scalpel.conf`, or copy it and pass the copy with `-c /path/to/new.conf` |
| Run | `scalpel -b -o /empty/output/directory DiskImage.img` |
| Add a custom file type | Add a line with extension, case sensitivity, max size, header, and footer, for example `txt y 10000 BTL1 1LTB` |
| Read recovered text | `strings /path/to/recovered/file` |

The output directory must be empty.

## Reading the Output

* Recovered files are named by offset, not by their original names, because carving does not use file system metadata
* Carving finds fragments and false positives, especially for types with short or common headers; check each result

## Related

* [File Systems](../file-systems.md)
* [Autopsy](autopsy.md)

## Resources

* [Scalpel Man Page](https://linux.die.net/man/1/scalpel)
* [Kali Tool Description](https://www.kali.org/tools/scalpel/)
* [PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec)
