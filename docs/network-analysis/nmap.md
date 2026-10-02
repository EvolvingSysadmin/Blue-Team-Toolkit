# Nmap

Network scanner for host discovery, port scanning, and service and OS detection.

## When I Use It

* Verifying what is actually exposed on a host or network segment, including from outside the firewall
* Checking that firewall rule changes did what they were supposed to
* Finding hosts and services missing from the asset inventory
* Seeing what an attacker's scan would have found

!!! warning "Only scan what you are authorized to scan"
    Get written approval before scanning networks you do not own or manage, and let the network team know, since scans can trip IDS alerts and occasionally disrupt fragile devices.

## Installation

* Linux: `sudo apt install nmap`
* Windows and macOS: download from <https://nmap.org/download.html>

## Common Tasks

| Option | Example | Description |
| :--- | :--- | :--- |
| -sS | `nmap -sS [target]` | SYN scan ("half-open"): sends SYN and does not complete the TCP handshake; default when run as root |
| -sT | `nmap -sT [target]` | TCP connect scan: completes the full handshake; default without root privileges |
| -sU | `nmap -sU [target]` | UDP scan |
| -sA | `nmap -sA [target]` | ACK scan: maps firewall rules (filtered vs unfiltered); does not identify open ports |
| -sn | `nmap -sn 192.168.1.0/24` | Host discovery only (ping sweep), no port scan |
| -Pn | `nmap -Pn [target]` | Skip host discovery and treat the target as up |
| -p | `nmap -p 22,80,443 [target]` / `nmap -p- [target]` | Specific ports / all 65535 ports |
| -sV | `nmap -sV [target]` | Service and version detection on open ports |
| -O | `nmap -O [target]` | OS detection |
| -A | `nmap -A [target]` | OS detection, version detection, default scripts, and traceroute |
| -T0 to -T5 | `nmap -T4 [target]` | Timing template, slowest to fastest |
| -v | `nmap -v [target]` | Verbose output |
| -oA | `nmap -oA scan1 [target]` | Save output in normal, XML, and grepable formats |

## Reading the Output

| State | Meaning |
| :--- | :--- |
| open | A service is accepting connections |
| closed | The host responded, but nothing is listening |
| filtered | No response or an ICMP error; a firewall is probably dropping the traffic |
| unfiltered | Reachable, but Nmap cannot tell whether open or closed (ACK scans) |

Recognizing Nmap in logs: many connection attempts from one source to many ports or hosts in a short time; SYN scans leave a pattern of SYN, SYN/ACK, then RST from the scanner; IDS signatures for port scans.

## Related

* [Common Ports](common-ports.md)
* [Wireshark](wireshark.md)
* [Critical CVE Response](../playbooks/operations/critical-cve-response.md)

## Resources

* [Nmap Reference Guide](https://nmap.org/book/man.html)
* [Port Scanning Techniques](https://nmap.org/book/man-port-scanning-techniques.html)
