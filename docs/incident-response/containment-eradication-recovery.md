# Containment, Eradication, and Recovery

## Containment

* Perimeter containment
  * Block inbound and outbound traffic
  * IDS/IPS filters to identify further malicious traffic and take automated actions, such as blocking active connections
  * Web Application Firewall policies to detect and act on web attacks
  * DNS sinkholing or null routing, so internal hosts cannot resolve a malicious domain
* Network containment
  * Switch-based VLAN isolation
  * Router-based segment isolation
  * Port blocking
  * IP or MAC address blocking
  * Access Control Lists (ACLs) to restrict what hosts can reach
* Endpoint containment
  * Isolate the host with EDR network containment where available
  * Disconnect the host from the network (disable Wi-Fi, unplug Ethernet)
  * Block traffic with the local firewall
  * Host intrusion prevention system (HIPS) actions
  * Capture volatile data such as memory before powering off; a shutdown destroys memory evidence
* Identity containment
  * Disable or reset compromised accounts
  * Revoke active sessions and tokens
  * Reset credentials that may have been exposed, including service accounts

## Eradication

* Remove malicious artifacts and persistence mechanisms
* Reimage compromised systems
* Close the access vector that was used

## Recovery

* Restore from known-good backups
* Patch systems and disable unneeded services
* Update EDR, antivirus, IDS/IPS, and SIEM rules with indicators from the incident
* Monitor restored systems closely for signs of reinfection
* Share intelligence with relevant partners
