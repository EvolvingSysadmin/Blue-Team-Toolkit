# Wireshark

* Description: used to capture and analyze network traffic in the form of packet capture files
* Installation: download from <https://www.wireshark.org/#download>
* Usage
  * Basic Capture Filter Examples
    * Capture Filters
    * Limit traffic to and from IP address: `host 192.168.1.1`
    * All traffic on the subnet: `net 192.168.0.0/24:`
    * Packets sent to the specified host: `dst host 192.168.1.1`
    * Limit traffic to port 53 only: `port 53`
    * All traffic except DNS/ARP: `port not 53 and not arp`
  * Basic Display Filter Examples
    * Packets sent from one computer (ip.src) to another (ip.dst): `ip.src==IP-address and ip.dst==IP-address`
    * Show you all traffic on port 25 (typically SMTP): `tcp.port eq 25`
    * Only show ICMP traffic: `icmp`
    * All traffic except traffic from specified IP: `ip.addr != IP_address`
    * Traffic from src host using TCP 443, using TLC version 1.2: `ip.src_host == 192.168.1.7 and tcp.port == 443 and ssl.record.version == 0x0303`
    * Show specific HTTP method: `http.request.method == "POST"`
    * Search for a string within a frame: `frame contains "string"`
    * Search strings within packets: CTRL + F
    * Host Identification from DHCP traffic: `ip.src==xxx.xxx.xxx && dhcp` then search for Host Name in the DHCP Options of a DHCP request packet
    * Search for http redirection: `http.reaspon.code==301` or search for the http.referer field
    * Search by port: `tcp.port`
    * More Display Filters here: <https://wiki.wireshark.org/DisplayFilters>
  * More Advanced Searching
    * To follow a packet stream: Right Click -> Follow > TCP/UDP/SSL/HTTP Stream
    * To extract HTTP files from packets: File -> Export Objects -> HTTP -> Highlight File -> Save As
    * To extract FTP files from packets: filter FTP-DATA packets for export -> Right Click -> Follow > TCP Stream -> Show and save data as Raw
    * To extract files from streams: Follow TCP Stream -> Save stream as raw -> Analyze with exif-tools or change file extension
      * Example: `frame contains 20210429_152157.jpg” -> Follow TCP Stream -> Save stream as raw` -> then analyze with exif-tools or change file extension to view
    * To search for domain names: Statistics -> Search for IP
    * To identify hostnames from DHCP traffic: `ip.src==xxx.xxx.xxx.xxx && dhcp` -> search for Host Name in the DHCP Options of a DHCP request packet
    * To search for http redirction: `http.response.code==301` or search for the http.referer field
    * Helpful Windows
      * Conversations
      * Protocol Hierarchy
      * Endpoints
* Resources
  * [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
  * [Wireshark Training Resources](https://www.wireshark.org/docs/)
  * [Into to Wireshark Video](https://www.youtube.com/watch?v=jvuiI1Leg6w)
  * [Wireshark Tutorial](https://www.varonis.com/blog/how-to-use-wireshark)
  * [Export Wireshark Data from TCP Stream](https://medium.com/@sshekhar01/cyberdefenders-packetmaze-beffc1d05cb)
  * [Identifying Hosts and Users using Wireshark](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
  