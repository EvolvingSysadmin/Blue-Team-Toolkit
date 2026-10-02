# Linux Logs

Log locations and search keywords for authentication, account, and system activity on Linux.

## Why It Matters

Linux servers run a lot of internet-facing services, and SSH is one of the most attacked services on the internet. The authentication log records who logged in, from where, and what they ran with sudo, which answers most early questions about a compromised Linux host.

## Reference

### Log Locations

| Log | Debian / Ubuntu | RHEL / CentOS / Fedora |
| :--- | :--- | :--- |
| Authentication, sudo, SSH | `/var/log/auth.log` | `/var/log/secure` |
| General system messages | `/var/log/syslog` | `/var/log/messages` |
| Successful logins and logouts | `/var/log/wtmp` (read with `last`) | Same |
| Failed logins | `/var/log/btmp` (read with `lastb`) | Same |
| systemd journal | `journalctl` | Same |

More locations are on the [Linux Artifacts](../endpoint-forensics/linux-artifacts.md) page.

### Search Keywords

| Activity | Keywords |
| :--- | :--- |
| Successful login | "Accepted password", "Accepted publickey", "session opened" |
| Failed login | "authentication failure", "Failed password", "Invalid user" |
| User added | "useradd", "new user" |
| User logoff | "session closed" |
| Account change or deletion | "password changed", "usermod", "userdel", "delete user" |
| Sudo use | "sudo:" with "COMMAND=", "FAILED su", "authentication failure" |
| Service failure | "failed", "failure" |

## How I Use It

I search the authentication log first, because it covers logins, sudo, and SSH in one place:

```bash
# Search all logs for a keyword
sudo grep -ri "search_keyword" /var/log/

# Include rotated and compressed logs
sudo zgrep -i "Failed password" /var/log/auth.log*

# Successful SSH logins with source IPs
sudo grep "Accepted" /var/log/auth.log

# Failed logins by source IP, most frequent first
sudo grep "Failed password" /var/log/auth.log | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn

# systemd journal for the SSH service in the last hour
sudo journalctl -u ssh --since "1 hour ago"
```

!!! warning "Logs on a compromised host can be edited"
    An attacker with root can modify or delete local logs. Logs forwarded to a central server or SIEM are much more trustworthy, and a gap or a missing file is evidence in its own right.

## Related

* [Linux Artifacts](../endpoint-forensics/linux-artifacts.md)
* [Syslog](syslog.md)
* [Log Review Approach](log-review-approach.md)

## Resources

* [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
