# Linux Artifacts

* Accounts and Password Hashes
  * `/etc/passwd`: every account on the system, with UID, home directory, and shell
  * `/etc/shadow`: password hashes and password aging information; readable only by root
    * Show contents: `sudo cat /etc/shadow`
  * `/etc/group` and `/etc/sudoers` (plus `/etc/sudoers.d/`): group membership and sudo rights
* Installed Software
  * Debian-based systems: `/var/lib/dpkg/status` or `dpkg -l`
  * Save all package names to a file: `grep Package /var/lib/dpkg/status > packages.txt`
  * RHEL-based systems: `rpm -qa`
* System Logs
  * `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL): authentication, sudo, and SSH activity
  * `/var/log/syslog` (Debian/Ubuntu) or `/var/log/messages` (RHEL): general system messages
  * `/var/log/dpkg.log`: packages installed or removed with `dpkg`/`apt`
  * `/var/log/wtmp`: logins and logouts, read with `last`
  * `/var/log/btmp`: failed logins, read with `lastb`
  * `/var/log/lastlog`: last login per user, read with `lastlog`
  * `/var/log/faillog`: failed login counters, read with `faillog`
  * `/var/log/cron` (RHEL) or cron entries in syslog (Debian/Ubuntu): cron job activity
  * systemd journal: `journalctl`
  * Search logs for a keyword (program name, malware name, IP): `grep -iRl "keyword" /var/log`
* Web Server Logs
  * `/var/log/apache2/access.log` or `/var/log/nginx/access.log`, including:
    * Client IP
    * Resource accessed
    * HTTP method
    * User-Agent
    * Request timestamp
  * More detail: [Web Server Logs](../siem-and-log-analysis/web-server-logs.md)
* User Files
  * Bash history: `cat ~/.bash_history` (and for root: `sudo cat /root/.bash_history`)
    * `history` shows the current shell's history; `history -c` clears it, so a missing or empty history file can itself be suspicious
  * User directories: Desktop, Downloads, Documents, and the trash at `~/.local/share/Trash`
  * Shell startup files that can be used for persistence: `~/.bashrc`, `~/.profile`
  * SSH keys: `~/.ssh/authorized_keys`
* Persistence Locations
  * Cron: `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/`, and `crontab -l` for each user
  * systemd services and timers: `/etc/systemd/system/`, `systemctl list-timers`
  * Legacy startup script: `/etc/rc.local`
* Network
  * Listening ports with processes: `ss -tulnp` (or `netstat -tulnp` on older systems)
  * Established connections: `ss -tunap`
