# Network Commands

Built-in Windows and Linux commands for checking a host's network configuration and connections.

## Why It Matters

On a host under investigation, these commands answer the first network questions without installing anything: what IP the host has, what it is connected to, what is listening, and whether a destination is reachable.

## Reference

| Task | Windows | Linux |
| :--- | :--- | :--- |
| IP configuration | `ipconfig /all` or `Get-NetIPConfiguration` | `ip a` |
| Routing table | `route print` | `ip r` |
| ARP cache | `arp -a` | `ip neigh` |
| Traceroute | `tracert [host]` | `traceroute [host]`; TCP to a port: `sudo traceroute -T -p 443 [host]` |
| DNS lookup | `nslookup [domain]` or `Resolve-DnsName [domain]` | `dig [domain]` |
| Mail servers | `Resolve-DnsName [domain] -Type MX` | `dig [domain] MX` |
| A record only | `Resolve-DnsName [domain] -Type A` | `dig [domain] A +short` |
| SPF and DMARC records | `Resolve-DnsName [domain] -Type TXT` | `dig [domain] TXT`, `dig _dmarc.[domain] TXT` |
| Connections with process IDs | `netstat -ano` or `Get-NetTCPConnection` | `ss -tunap` |
| Listening ports with processes | `netstat -abno` (requires administrator) | `ss -tulnp` (or `netstat -tulnp` on older systems) |
| Protocol statistics | `netstat -s` | `netstat -s` or `nstat` |
| Ping | `ping -n 4 [host]` | `ping -c 4 [host]` |
| Test a TCP port | `Test-NetConnection [host] -Port 443` | `nc -zv [host] 443` |

## How I Use It

On a suspect Windows host, `netstat -ano` and `Get-NetTCPConnection` tie connections to process IDs, which I then look up with `tasklist` or `Get-Process`. An established connection to an unfamiliar public IP from a process that should not be talking to the internet is one of the quickest leads there is. I record the output before containing the host, because isolation ends those connections.

## Related

* [Common Ports](common-ports.md)
* [Windows Artifacts](../endpoint-forensics/windows-artifacts.md)
* [Linux Artifacts](../endpoint-forensics/linux-artifacts.md)
