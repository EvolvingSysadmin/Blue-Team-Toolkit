# Wireshark

* Description: used to capture and analyze network traffic and packet capture (pcap) files
* Installation: download from <https://www.wireshark.org/download.html>
* Usage
  * Capture Filters (BPF syntax, set before a capture starts)
    * Traffic to and from an IP address: `host 192.168.1.1`
    * All traffic on a subnet: `net 192.168.0.0/24`
    * Packets sent to a host: `dst host 192.168.1.1`
    * Port 53 only: `port 53`
    * All traffic except DNS and ARP: `not port 53 and not arp`
  * Display Filters (applied to captured traffic)
    * Packets from one host to another: `ip.src == 10.0.0.5 and ip.dst == 10.0.0.10`
    * All traffic to or from a host: `ip.addr == 10.0.0.5`
    * All traffic except a host: `!(ip.addr == 10.0.0.5)`
    * TCP port 25 (SMTP): `tcp.port == 25`
    * ICMP only: `icmp`
    * TLS traffic from a host on port 443: `ip.src == 192.168.1.7 and tcp.port == 443 and tls`
    * TLS server names (SNI): `tls.handshake.extensions_server_name contains "example"`
    * DNS queries for a domain: `dns.qry.name contains "example"`
    * HTTP method: `http.request.method == "POST"`
    * HTTP redirects: `http.response.code == 301 or http.response.code == 302`, or check the `http.referer` field
    * String within a frame: `frame contains "string"`
    * Hostnames from DHCP: `dhcp` then check the Host Name option in DHCP Request packets
    * SYN scan pattern: `tcp.flags.syn == 1 and tcp.flags.ack == 0`
    * More display filters: <https://wiki.wireshark.org/DisplayFilters>
  * Searching and Extracting
    * Search for strings within packets: Ctrl + F
    * Follow a stream: right click -> Follow -> TCP/UDP/TLS/HTTP Stream
    * Extract files from HTTP traffic: File -> Export Objects -> HTTP -> select file -> Save
    * Extract files from FTP traffic: filter `ftp-data` -> right click -> Follow -> TCP Stream -> Show data as Raw -> Save
    * Extract files from other streams: Follow TCP Stream -> Show data as Raw -> Save, then analyze with ExifTool or fix the file extension
      * Example: filter `frame contains "20210429_152157.jpg"` -> Follow TCP Stream -> save as raw -> open with ExifTool or as a .jpg
    * Resolved hostnames seen in the capture: Statistics -> Resolved Addresses
  * Helpful Statistics Windows
    * Conversations
    * Protocol Hierarchy
    * Endpoints
* TShark: command line version of Wireshark, useful for large captures and scripting
  * Apply a display filter to a pcap: `tshark -r capture.pcap -Y "http.request"`
  * Print selected fields: `tshark -r capture.pcap -Y dns -T fields -e ip.src -e dns.qry.name`
* Resources
  * [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
  * [Wireshark Documentation](https://www.wireshark.org/docs/)
  * [TShark Manual](https://www.wireshark.org/docs/man-pages/tshark.html)
  * [Intro to Wireshark Video](https://www.youtube.com/watch?v=jvuiI1Leg6w)
  * [Wireshark Tutorial](https://www.varonis.com/blog/how-to-use-wireshark)
  * [Export Wireshark Data from TCP Stream](https://medium.com/@sshekhar01/cyberdefenders-packetmaze-beffc1d05cb)
  * [Identifying Hosts and Users using Wireshark](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
