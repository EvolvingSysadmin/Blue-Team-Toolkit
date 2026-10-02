# File Systems

Common Windows and Linux file systems and the structures that are useful in an investigation.

## Why It Matters

The file system decides what evidence exists: whether there is a journal of changes, what timestamps are kept, whether deleted files can be recovered, and where data can hide. Knowing what a file system records tells you what questions a disk image can answer.

## Reference

### File System Comparison

| File System | Used By | Max File Size | Journaling | Notes |
| :--- | :--- | :--- | :--- | :--- |
| FAT16 | DOS, early Windows | 2 GB to 4 GB | No | Files can be lost if the allocation table is damaged |
| FAT32 | USB drives, SD cards, boot partitions | 4 GB | No | Max volume 2 TB with 512-byte sectors; no permissions, compression, or encryption |
| exFAT | Large USB drives, SD cards | Effectively unlimited | No | Designed for flash storage |
| NTFS | Windows | Effectively unlimited | Yes | ACL permissions, compression, EFS encryption |
| EXT3 | Linux | Up to 2 TB | Yes | Added journaling to EXT2 |
| EXT4 | Linux | 16 TiB | Yes | Volumes up to 1 EiB; uses extents to reduce fragmentation |

### NTFS Structures

| Structure | What It Records |
| :--- | :--- |
| `$MFT` | Master File Table: a record for every file and directory, including timestamps |
| `$LogFile` | NTFS transaction journal |
| `$UsnJrnl:$J` | Update sequence number journal: a log of file creations, deletions, renames, and changes |
| Alternate Data Streams (ADS) | Hidden streams attached to files, including `Zone.Identifier` (Mark of the Web) on downloads |

### Linux File I/O Path

| Layer | Role |
| :--- | :--- |
| User space | An application makes a system call |
| Kernel space | The kernel handles the request through the virtual file system and file system driver |
| Disk | The device driver performs the I/O |

## How I Use It

On Windows cases, the `$MFT` and `$UsnJrnl` are where I go to build a file timeline, since they record activity even after files are deleted. MFTECmd from Eric Zimmerman's tools parses both into CSV for Timeline Explorer. [FTK Imager](tools/ftk-imager.md) shows the file system type and structure of an image before deeper analysis.

!!! tip "Timestamps can be faked"
    Attackers can change a file's standard timestamps (timestomping). In NTFS, the `$FILE_NAME` attribute keeps its own timestamps that are much harder to change, so a mismatch between the two is a useful clue.

## Related

* [File Metadata](file-metadata.md)
* [Windows Artifacts](windows-artifacts.md)
* [Autopsy](tools/autopsy.md)

## Resources

* [Eric Zimmerman's Tools](https://ericzimmerman.github.io/)
* [The Sleuth Kit](https://www.sleuthkit.org/)
