# Linux Artifacts

* Password Hashes
  * Passwd file: `/etc/passwd` file is used to keep track of every registered user that has access to a system
  * Shadow file: `/etc/shadow` file contains encrypted passwords as well as other information such as account or password expiration values
    * To show shadow file content: `sudo cat /etc/shadow`
* Installed Software
  * Find installed software on Debian based systems by checking the status file: `/var/lib/dpkg/status`
  * Save all lines that contain package in `/var/lib/dpkg/status` to packages.txt: `cat status | grep Package > packages.txt`
* System Logs
  * `/var/log/auth.log`: system authorizations, including user logins
  * `/var/log/dpkg.log`: packages installed or removed using the `dpkg` command
  * `/var/log/btmp`: failed login attempts
  * `/var/log/cron`: cron jobs
  * `/var/log/secure`: authentication and authorization privileges (eg related to SSH)
  * `/var/log/faillog`: failedf user logins
  * To search linux logs for a specific program/malware: `/var/log$ grep -iRl {keyword}`
* Web Server Logs for Apache and Nginx
  * `var/log/apache2/access.log`: shows web server info in Apache, including:
    * Client IP
    * Resource accessed
    * HTTP method
    * User-Agent of client IP
    * Request timestamps
* User Files
  * Bash History
    * `cd ~`
    * `ls -a`
    * `cat .bash_history`
    * `history` can also be used, but `history -c` can be used to delete terminal history
  * Clear Files
    * Desktop, Downloads, Music, Pictures, Public, Templates, Videos
    * Trash Bin
  * Super user startup scripts: `/etc/rc.local`
  * To show listening network connections: `netstat -tulnp`
  