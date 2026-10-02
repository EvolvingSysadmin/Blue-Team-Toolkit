# Wireshark

Packet capture and analysis tool, with TShark as its command line counterpart.

## When I Use It

* Analyzing a packet capture from an incident or an IDS alert
* Confirming what a suspicious host is actually sending, beyond what flow logs show
* Extracting files and credentials transferred in cleartext protocols
* Practicing with capture-based challenges

## Installation

* Download from <https://www.wireshark.org/download.html>
* Linux: `sudo apt install wireshark` (TShark: `sudo apt install tshark`)

## Common Tasks

### Capture Filters

BPF syntax, set before a capture starts to limit what is recorded.

| Goal | Filter |
| :--- | :--- |
| Traffic to and from an IP | `host 192.168.1.1` |
| A subnet | `net 192.168.0.0/24` |
| Packets sent to a host | `dst host 192.168.1.1` |
| One port | `port 53` |
| Everything except DNS and ARP | `not port 53 and not arp` |

### Display Filters

Applied to captured traffic.

| Goal | Filter |
| :--- | :--- |
| Traffic from one host to another | `ip.src == 10.0.0.5 and ip.dst == 10.0.0.10` |
| All traffic for a host | `ip.addr == 10.0.0.5` |
| All traffic except a host | `!(ip.addr == 10.0.0.5)` |
| A TCP port | `tcp.port == 25` |
| ICMP only | `icmp` |
| TLS from a host on port 443 | `ip.src == 192.168.1.7 and tcp.port == 443 and tls` |
| TLS server names (SNI) | `tls.handshake.extensions_server_name contains "example"` |
| DNS queries for a domain | `dns.qry.name contains "example"` |
| HTTP POST requests | `http.request.method == "POST"` |
| HTTP redirects | `http.response.code == 301 or http.response.code == 302` |
| A string anywhere in a frame | `frame contains "string"` |
| DHCP (hostnames are in the Host Name option of DHCP Requests) | `dhcp` |
| SYN scan pattern | `tcp.flags.syn == 1 and tcp.flags.ack == 0` |

### Searching and Extracting

| Task | Steps |
| :--- | :--- |
| Search packets for a string | Ctrl + F |
| Follow a conversation | Right click -> Follow -> TCP/UDP/TLS/HTTP Stream |
| Extract files from HTTP | File -> Export Objects -> HTTP -> select file -> Save |
| Extract files from FTP | Filter `ftp-data` -> right click -> Follow -> TCP Stream -> Show data as Raw -> Save |
| Extract files from other streams | Follow TCP Stream -> Show data as Raw -> Save, then check with ExifTool or fix the file extension |
| Resolved hostnames | Statistics -> Resolved Addresses |

### TShark

```bash
# Apply a display filter to a capture
tshark -r capture.pcap -Y "http.request"

# Print selected fields: source IP and DNS query name
tshark -r capture.pcap -Y dns -T fields -e ip.src -e dns.qry.name
```

## Reading the Output

I start with the statistics windows before reading individual packets:

| Window | What It Shows |
| :--- | :--- |
| Statistics -> Protocol Hierarchy | Which protocols are in the capture, and how much of each |
| Statistics -> Conversations | Which hosts talked to each other, and how much data moved |
| Statistics -> Endpoints | Every host in the capture, sortable by traffic |

A host sending far more data out than it receives, or a protocol that should not be there (SMB to the internet, DNS to a server that is not your resolver), is where I dig in.

## Related

* [Network Commands](network-commands.md)
* [Common Ports](common-ports.md)
* [C2 Beaconing](../playbooks/threat-hunting/c2-beaconing.md) hunt
* [ExifTool](../endpoint-forensics/tools/exiftool.md)

## Resources

* [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
* [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters)
* [TShark Manual](https://www.wireshark.org/docs/man-pages/tshark.html)
* [Wireshark Tutorial (Varonis)](https://www.varonis.com/blog/how-to-use-wireshark)
* [Identifying Hosts and Users using Wireshark (Unit 42)](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [Export Wireshark Data from TCP Stream](https://medium.com/@sshekhar01/cyberdefenders-packetmaze-beffc1d05cb)
