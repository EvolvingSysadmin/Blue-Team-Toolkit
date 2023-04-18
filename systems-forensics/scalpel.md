# Scalpel

* Description: used to retrieve deleted files from .img files by using file carving
* Linux installation: `sudo apt-get install scalpel`
* Usage
  * Edit scalpel.conf to uncomment the type of files hoping to get from an .img file by doing one of the following
    * Manually edit the file by using the GUI to navigate to:  `/etc/scalpel/scalpel.conf` and uncomment relevent file types
    * Use vim or nano `sudo nano /etc/scalpel/scalpel.conf` and uncomment relevent file types
    * Create a copy of the `/etc/scalpel/scalpel.conf`, uncomment relevent file types, and then specify that file when using scalpel by using: `scalpel -c /path/to/new/conf.conf`
  * Create an empty output directory
  * Run command: `scalpel -b -o /empty/output/directory DiskImage.img`
    * Example: `scalpel -b -o /root/Desktop/ScalpelOutput DiskImage1.img`
  * Note: scalpel can be configured to search for document types with custom headers and footers by editing the configuration file:
    * Example for files with "BTL1" header and "1LTB" footer: create a new line on the .conf file with `txt y 10000 BTL1 1LTB`
    * To show strings from a recovered file: `strings path\to\txt`
* Resources
* [https://linux.die.net/man/1/scalpel](Scalpel Man Page)
  * [Kali Tool Description](https://www.kali.org/tools/scalpel/)
  * [Scalpel Guide](https://www.tecmint.com/install-scalpel-a-filesystem-recovery-tool-to-recover-deleted-filesfolders-in-linux/)
  