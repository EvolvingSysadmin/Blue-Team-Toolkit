# Linux Log Analysis

* Description: keywords to search for in linux logs for log analysis
* Usage: `sudo grep -r "search_keyword" /var/log *`
* Search Keywords
  * Successful User Login
    * “Accepted password”, “Accepted publickey”, "session opened”
  * Failed User Login
    * “authentication failure”, “failed password”
  * User added
    * "adduser" or "useradd"
  * User Logoff
    * “session closed”
  * User account change or deletion
    * “password changed”, “new user”, “delete user”
  * Sudo Actions
    * “sudo: … COMMAND=…”“FAILED su”
  * Service Failure
    * “failed” or “failure”
* Resources
  * [Searching Log Files](https://www.jungledisk.com/blog/2018/02/15/learning-linux-searching-log-files/)
  * [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
