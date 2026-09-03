# Memory File Analysis

* Pagefile.sys: used within Windows operating systems to store data from the RAM when it becomes full
  * Pagefile Location: `C:\pagefile.sys`
  * To show the hidden pagefile: `dir /a:h c:`
* Swapfile used as RAM swap space in Linux, usually in its own partition
  * To adjust swapfile size: `sudo fallocate -l [file size] /swapfile`
  * To check the ammount of swap space: `free -h`
  * To show if the swap space is a file or a partition`swapon –show`
* Hiberation file: allows operating system to store current memory state to `hiberfil.sys`
