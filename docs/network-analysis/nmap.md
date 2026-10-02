# Nmap

* Description: network scanner for host discovery, port scanning, service and OS detection
* Installation: `sudo apt install nmap` or download from <https://nmap.org/download.html>
* Defenders use Nmap to verify exposed services and firewall rules, build asset inventories, and confirm what an attacker's scan would have seen

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

* Detecting Nmap scans
  * Many connection attempts from one source to many ports or hosts in a short time
  * SYN scans leave half-open connections: SYN, SYN/ACK, then RST from the scanner
  * Firewall and IDS logs (for example Suricata or Snort port scan signatures)
* Resources
  * [Nmap Reference Guide](https://nmap.org/book/man.html)
  * [Port Scanning Techniques](https://nmap.org/book/man-port-scanning-techniques.html)
