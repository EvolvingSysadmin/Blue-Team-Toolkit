# FTK Imager

Free imaging tool for capturing memory, creating and verifying disk images, and previewing evidence.

## When I Use It

* Capturing memory from a live Windows system
* Creating a forensic image of a disk or USB drive
* Quickly previewing the contents of an image, or exporting specific files from it, without a full analysis platform

## Installation

* Download from <https://www.exterro.com/digital-forensics-software/ftk-imager>
* For live collection, run it from external media to avoid writing to the system under investigation

## Common Tasks

| Task | Steps |
| :--- | :--- |
| Capture memory | File -> Capture Memory -> destination on external media; optionally include the pagefile |
| Create a disk image | File -> Create Disk Image -> select source -> choose format (Raw/dd or E01) -> add case details -> Start |
| Verify an image | File -> Verify Drive/Image (compares MD5 and SHA1 hashes) |
| Preview an image | File -> Add Evidence Item -> Image File |
| Export files from an image | Right click a file or folder -> Export Files |
| Mount an image read-only | File -> Image Mounting |

## Reading the Output

* Every image creation produces a log with the hashes of the source and the image; keep it with the evidence
* E01 images compress and store case metadata; raw images are larger but readable by almost any tool

!!! warning "Use a write-blocker for physical drives"
    When imaging a disk removed from a system, connect it through a hardware write-blocker so nothing is written to the original.

## Related

* [Evidence Handling](../evidence-handling.md)
* [Memory Artifacts](../memory-artifacts.md)
* [Autopsy](autopsy.md), for analyzing the image

## Resources

* [Comprehensive Guide on FTK Imager](https://www.hackingarticles.in/comprehensive-guide-on-ftk-imager/)
