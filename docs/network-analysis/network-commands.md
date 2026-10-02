# Basic Network Tools

* IP information
  * Windows: `ipconfig /all`
  * Linux: `ip -aip r`
* Routing tables
  * Windows: `route print`
  * Linux: `ip r list`
* Traceroute
  * Windows: `tracert [URL]`
  * Linux: `traceroute [url] -p [port number]`
* DNS
  * Windows: `nslookup [domain name]`
  * Linux: `dig [domain name]`
  * Linux email DNS info: `dig [domain name] mx`
  * Linux get A record: `dig [domain name] ANY +nocomments +noauthority +noadditional +nostats`
* Netstat
  * Windows and Linux current connections/listening ports: `netstat -a`
  * Windows current connections/ports/related executables: `netstat -a -b`
  * Windows and Linux statistics for all connections using TCP: `netstat -s -p tcp -f`
* PING
  * Linux: `sudo ping -v [target]`
  * Linux ping summary: `ping -c 5 -q [target]`
