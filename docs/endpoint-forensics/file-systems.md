# File Systems

* FAT16: File Allocation Table file system used by DOS and early Windows; the table records where each file's clusters are, so files can be lost if the FAT is damaged
* FAT32: 32-bit version of FAT with support for much larger volumes
  * Compatible with almost every operating system and device, so it is still common on USB drives and SD cards
  * Limitations
    * Maximum file size of 4 GB
    * Maximum volume size of 2 TB with 512-byte sectors
    * No journaling, so no protection from corruption on power loss
    * No file permissions, compression, or encryption
* exFAT: designed for flash storage; removes the 4 GB file size limit; common on large USB drives and SD cards
* NTFS: Microsoft file system since Windows NT 3.1
  * Journaling, ACL-based permissions, compression, encryption (EFS), and much larger file and volume sizes than FAT
  * Forensically useful structures
    * `$MFT`: Master File Table, with a record for every file including timestamps
    * `$LogFile`: NTFS transaction journal
    * `$UsnJrnl:$J`: update sequence number journal, a log of file changes
    * Alternate Data Streams (ADS): hidden streams attached to files, including `Zone.Identifier` (Mark of the Web) on downloaded files
* EXT3/EXT4: common Linux file systems
  * EXT3: added journaling to EXT2 for resiliency
  * EXT4: supports volumes up to 1 exbibyte and files up to 16 tebibytes; uses extents (contiguous block ranges) to reduce fragmentation
* Linux file I/O path
  * User space: an application makes a system call
  * Kernel space: the kernel handles the request through the virtual file system and file system driver
  * Disk: the device driver performs the I/O on the disk
* FTK Imager can display the file system type and structure of a disk image
