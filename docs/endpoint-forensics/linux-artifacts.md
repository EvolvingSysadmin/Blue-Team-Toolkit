# Linux Artifacts

Where Linux records accounts, logins, commands, installed software, and persistence.

## Why It Matters

Linux servers often run internet-facing services and rarely have the same endpoint monitoring as Windows workstations. The artifacts on the host are frequently the main evidence of how an attacker got in and what they did.

## Reference

### Accounts and Credentials

| File | Contents |
| :--- | :--- |
| `/etc/passwd` | Every account, with UID, home directory, and shell |
| `/etc/shadow` | Password hashes and password aging; readable only by root |
| `/etc/group` | Group membership |
| `/etc/sudoers`, `/etc/sudoers.d/` | Who can run what with sudo |
| `~/.ssh/authorized_keys` | Public keys allowed to log in as the user |

### Logs

| Log | Contents | Read With |
| :--- | :--- | :--- |
| `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL) | Authentication, sudo, SSH | `grep`, `less` |
| `/var/log/syslog` (Debian/Ubuntu), `/var/log/messages` (RHEL) | General system messages | `grep`, `less` |
| `/var/log/wtmp` | Logins and logouts | `last` |
| `/var/log/btmp` | Failed logins | `lastb` |
| `/var/log/lastlog` | Last login per user | `lastlog` |
| `/var/log/faillog` | Failed login counters | `faillog` |
| `/var/log/dpkg.log` | Packages installed or removed | `grep`, `less` |
| `/var/log/cron` (RHEL), syslog (Debian/Ubuntu) | Cron job activity | `grep` |
| `/var/log/apache2/access.log`, `/var/log/nginx/access.log` | Web requests | See [Web Server Logs](../siem-and-log-analysis/web-server-logs.md) |
| systemd journal | All of the above on systemd systems | `journalctl` |

### Installed Software

| Distribution | Command |
| :--- | :--- |
| Debian / Ubuntu | `dpkg -l`, or `grep Package /var/lib/dpkg/status` |
| RHEL / Fedora | `rpm -qa` |

### User Activity

| Artifact | Location |
| :--- | :--- |
| Bash history | `~/.bash_history`, `/root/.bash_history` |
| Shell startup files | `~/.bashrc`, `~/.profile` |
| Trash | `~/.local/share/Trash` |
| User directories | Desktop, Downloads, Documents |
| World-writable staging areas | `/tmp`, `/var/tmp`, `/dev/shm` |

### Persistence Locations

| Mechanism | Location |
| :--- | :--- |
| Cron | `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/`, `crontab -l` for each user |
| systemd services and timers | `/etc/systemd/system/`, `~/.config/systemd/user/`, `systemctl list-timers` |
| Shell startup files | `~/.bashrc`, `~/.profile`, `/etc/profile.d/` |
| SSH keys | `~/.ssh/authorized_keys` |
| Legacy startup script | `/etc/rc.local` |

!!! warning "A missing history is evidence too"
    `history -c` clears the current shell's history, and attackers often unset `HISTFILE` or link `.bash_history` to `/dev/null`. An empty or missing history file on an active account is worth noting.

## How I Use It

I start with `auth.log` or `secure` to see who logged in and from where, then `last` and `lastb` for login history, then bash history for the accounts involved. After that I check every persistence location in the table above, because attackers on Linux almost always leave a cron job, a systemd service, or an SSH key behind. Network state comes from `ss -tunap` and `ss -tulnp`.

## Related

* [Linux Logs](../siem-and-log-analysis/linux-logs.md)
* [John the Ripper](tools/john-the-ripper.md)
* [Persistence](../playbooks/threat-hunting/persistence.md) hunt

## Resources

* [SANS DFIR Posters and Cheat Sheets](https://www.sans.org/posters/)
