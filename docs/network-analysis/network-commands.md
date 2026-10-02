# Network Commands

* IP information
  * Windows: `ipconfig /all` or `Get-NetIPConfiguration`
  * Linux: `ip a`
* Routing tables
  * Windows: `route print`
  * Linux: `ip r`
* ARP cache
  * Windows: `arp -a`
  * Linux: `ip neigh`
* Traceroute
  * Windows: `tracert [host]`
  * Linux: `traceroute [host]`; TCP traceroute to a specific port: `sudo traceroute -T -p 443 [host]`
* DNS
  * Windows: `nslookup [domain]` or `Resolve-DnsName [domain]`
  * Linux: `dig [domain]`
  * Mail servers: `dig [domain] MX`
  * A record only: `dig [domain] A +short`
  * TXT records (SPF, DMARC): `dig [domain] TXT` and `dig _dmarc.[domain] TXT`
* Connections and listening ports
  * Windows: `netstat -ano` (connections with PIDs), `netstat -ab` (with executable names, requires administrator), `Get-NetTCPConnection`
  * Linux: `ss -tulnp` (listening TCP/UDP with processes), `ss -tunap` (all connections); `netstat -tulnp` on older systems
  * Protocol statistics: `netstat -s`
* Connectivity
  * Ping: `ping -n 4 [host]` (Windows), `ping -c 4 [host]` (Linux)
  * Test a TCP port from Windows: `Test-NetConnection [host] -Port 443`
  * Test a TCP port from Linux: `nc -zv [host] 443`
