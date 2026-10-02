# Linux Logs

* Description: keywords to search for in Linux logs during log analysis
* Usage
  * Search all logs for a keyword: `sudo grep -ri "search_keyword" /var/log/`
  * Include rotated, compressed logs: `sudo zgrep -i "search_keyword" /var/log/auth.log*`
  * On systemd distributions, search the journal: `sudo journalctl | grep -i "search_keyword"` or `sudo journalctl -u ssh --since "1 hour ago"`
* Authentication log location
  * Debian/Ubuntu: `/var/log/auth.log`
  * RHEL/CentOS/Fedora: `/var/log/secure`
* Search Keywords
  * Successful user login
    * "Accepted password", "Accepted publickey", "session opened"
  * Failed user login
    * "authentication failure", "Failed password", "Invalid user"
  * User added
    * "useradd", "new user"
  * User logoff
    * "session closed"
  * User account change or deletion
    * "password changed", "usermod", "userdel", "delete user"
  * Sudo actions
    * "sudo:" with "COMMAND=", "FAILED su", "authentication failure" for sudo
  * Service failure
    * "failed" or "failure"
* Resources
  * [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
  * [Linux Artifacts](../endpoint-forensics/linux-artifacts.md)
