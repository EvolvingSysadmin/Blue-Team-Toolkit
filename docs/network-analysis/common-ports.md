# Common Ports

Port ranges and the ports that come up most often in investigations.

## Why It Matters

Ports are the first clue to what a connection is: an internal workstation talking to another workstation on 445 or 3389 looks very different from a browser on 443. They also show what a host or firewall is exposing.

## Reference

### Port Ranges

| Range | Name |
| :--- | :--- |
| 0 to 1023 | Well-known (system) ports |
| 1024 to 49151 | Registered ports |
| 49152 to 65535 | Dynamic (private or ephemeral) ports |

### Ports and Services

| Port | Protocol | Service |
| :--- | :--- | :--- |
| 20, 21 | TCP | FTP |
| 22 | TCP | SSH, SFTP |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 53 | UDP, TCP | DNS |
| 67, 68 | UDP | DHCP |
| 80 | TCP | HTTP |
| 88 | TCP, UDP | Kerberos |
| 110, 995 | TCP | POP3, POP3 over TLS |
| 123 | UDP | NTP |
| 135 | TCP | Microsoft RPC endpoint mapper |
| 137 to 139 | UDP, TCP | NetBIOS |
| 143, 993 | TCP | IMAP, IMAP over TLS |
| 161, 162 | UDP | SNMP |
| 389, 636 | TCP | LDAP, LDAPS |
| 443 | TCP | HTTPS |
| 445 | TCP | SMB |
| 465, 587 | TCP | SMTP submission |
| 514 | UDP | Syslog |
| 1433 | TCP | Microsoft SQL Server |
| 3306 | TCP | MySQL |
| 3389 | TCP, UDP | RDP |
| 5985, 5986 | TCP | WinRM (HTTP, HTTPS) |
| 6514 | TCP | Syslog over TLS |

## How I Use It

I pay most attention to ports used for remote access and lateral movement (22, 135, 445, 3389, 5985, 5986) when the source is a workstation, and to anything administrative exposed to the internet. Ports are only a convention, though: attackers run C2 over 443 to blend in, so a familiar port does not make a connection safe.

## Related

* [Network Commands](network-commands.md)
* [Nmap](nmap.md)

## Resources

* [IANA Service Name and Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
