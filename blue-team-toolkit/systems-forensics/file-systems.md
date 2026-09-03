# File Systems

* FAT16: File Allocation Table, uses a table to mark the position of the files; used by DOS and Windows 3.X; files can be lost of the FAT is lost/damaged
* FAT32: FAT16 but with larger partitions for long filenames; uses 32 bits of data for identifying data clusters
  * FAT32 is compatable with many devices and is cross compatible with all modern operating systems since 1995
  * FAT32 disadvantages:
    * Only >4GB files
    * 8TB max capacity
    * No data protection from power loss
    * No built in compression
    * No built in encryption
* NTFS: Microsoft file system since Windows NT 3.1
  * Improved performance, reliability, security (ACLs) and disk space from FAT
* Linux architecture for EXT3 and EXT4
  * User space: user space -> sends to system call -> requeast sent to kernel
  * Kernel space: operating system core -> provides requested resources to user space, manages io/memory/file management
  * Disk space: kernal space device driver io request -> hard disk
* EXT3/EXT4
  * EXT3: default file system for many popular Linux distributions; uses journaling for resiliency
  * EXT4: maximum volume size of data supported by ext4 is 1exbibyte and file size is up to 16 tebibytes; uses extents which is a data storage area that reduces file fragmentation and file scattering
* FTK Imager can be used to show file types of disk images
