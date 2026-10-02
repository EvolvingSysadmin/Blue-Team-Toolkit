# Scalpel

* Description: recovers deleted files from disk images by file carving (searching for known file headers and footers)
* Linux installation: `sudo apt install scalpel`
* Usage
  * Edit scalpel.conf and uncomment the file types to recover, by one of these methods:
    * Edit `/etc/scalpel/scalpel.conf` directly: `sudo nano /etc/scalpel/scalpel.conf`
    * Copy `/etc/scalpel/scalpel.conf`, edit the copy, and pass it with `-c /path/to/new.conf`
  * Create an empty output directory
  * Run: `scalpel -b -o /empty/output/directory DiskImage.img`
    * Example: `scalpel -b -o /root/Desktop/ScalpelOutput DiskImage1.img`
  * Custom file types can be added to the config with a header and footer
    * Example for text files with the header "BTL1" and footer "1LTB": add the line `txt y 10000 BTL1 1LTB`
    * Show strings from a recovered file: `strings /path/to/recovered/file`
* Scalpel is no longer actively developed; Foremost and PhotoRec are common alternatives
* Resources
  * [Scalpel Man Page](https://linux.die.net/man/1/scalpel)
  * [Kali Tool Description](https://www.kali.org/tools/scalpel/)
  * [Scalpel Guide](https://www.tecmint.com/install-scalpel-a-filesystem-recovery-tool-to-recover-deleted-filesfolders-in-linux/)
  * [PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec)
