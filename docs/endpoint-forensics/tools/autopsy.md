# Autopsy

Open source digital forensics platform built on The Sleuth Kit, for analyzing disk images through a graphical interface.

## When I Use It

* Full analysis of a disk image when I need to browse the file system, recover deleted files, and search across everything
* Building a timeline of file activity on a system
* Cases where a GUI is faster than chaining command line tools, or where I need to show findings to someone else

## Installation

* Download from <https://www.autopsy.com/download/>
* Windows installer, or a Linux and macOS package that needs Java and The Sleuth Kit

## Common Tasks

| Task | Steps |
| :--- | :--- |
| Start a case | Case -> New Case -> name and folder -> Add Data Source |
| Add evidence | Disk image (E01, raw/dd), local disk, logical files, or virtual machine disk |
| Run analysis | Choose ingest modules when adding the data source |
| Search | Keyword Search panel, using exact match, substring, or regular expressions |
| Review results | The tree on the left: Views (by file type, date), Results (keyword hits, hash hits, interesting items), Tags |
| Timeline | Tools -> Timeline |
| Report | Generate Report -> HTML, Excel, or other formats |

### Useful Ingest Modules

| Module | What It Does |
| :--- | :--- |
| Recent Activity | Browser history, recent documents, USB devices, installed programs |
| Hash Lookup | Flags known-bad files and filters known-good ones using hash sets |
| File Type Identification | Identifies files by signature, not extension |
| Extension Mismatch Detector | Files whose extension does not match their content |
| Keyword Search | Indexes text for searching, including Unicode string extraction |
| Email Parser | MBOX and PST email |
| Interesting Files Identifier | Files matching rules you define |
| Embedded File Extractor | Contents of archives and Office documents |

## Reading the Output

* Results under "Extension Mismatch" and "Interesting Items" are worth checking early; renamed executables show up there
* Deleted files appear with a red X; whether they can be recovered depends on whether the space was reused
* Ingest runs in the background, so results keep appearing while analysis continues

## Related

* [FTK Imager](ftk-imager.md), to create the image
* [File Systems](../file-systems.md)
* [Windows Artifacts](../windows-artifacts.md)

## Resources

* [Autopsy User Guide](https://sleuthkit.org/autopsy/docs/user-docs/latest/)
* [The Sleuth Kit](https://www.sleuthkit.org/)
