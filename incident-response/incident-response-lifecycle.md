# Incident Response Lifecycle

* Incident Response Lifecycle: Preparation -> Detection and Analysis -> Containment, Eradication, and Recovery -> Lessons Learned and Reporting
* Phases
  * Preparation
    * Incident Response Plans Should Include the Following Sections:
    * Preparation
    * Identification
    * Containment
    * Eradication
    * Recovery
    * Lessons Learned
      * Example Incident Response Plans
        * [Carnegie Mellon University](https://www.cmu.edu/iso/governance/procedures/docs/incidentresponseplan1.0.pdf)
        * [Wright State University](https://www.wright.edu/information-technology/policies)
        * Create Incident Response Team and conduct training and create incident response run books
        * [Microsoft Run Books](https://docs.microsoft.com/en-us/security/compass/incident-response-playbooks)
        * [Run book examples](https://www.incidentresponse.org/playbooks/)
      * Create asset-inventories
      * Run risk assessments
      * Enact defensive measures, eg DMZ, NIDS/HIDS/NIPS, AV, Centralized Logging, EDR, Network Firewalls, Local Firewalls, WAFs, GPOs, NAC, web proxies, SPF/DKIM/DMARC, mark external emails, use email spam filters, DLP, sandboxing, attachment file restrictions, physical defenses, awareness training, phishing simulations, etc...
  * Detection and Analysis
    * Identify scanning, including:
    * Remote to Local Scanning (R2L): Search for HTTP connections of non standard ports
    * Remote to Local DoS/DDoS (L2R): search for anamolus traffic that differs from baselines
    * Local to Local Scanning (L2L): internal vulnerability scanners
    * Login Failures: search for windows event ID 4625
  * Containment
    * Perimeter containment
      * Block inbound traffic and outbound traffic.
      * IDS/IPS Filters to identify further malicious traffic and take automated actions, such as blocking active connections.
      * Web Application Firewall policies, to detect and take action against web attacks.
      * Null route DNS, to prevent DNS resolutions so internal hosts cannot find the IP address of a given domain name and establish a connection.
    * Network containment
      * Switch-based VLAN isolation, to restrict network access.
      * Router-based segment isolation, to restrict network access.
      * Port blocking, to prevent connections on specific ports.
      * IP or MAC Address blocking, to restrict network access.
      * Access Control Lists (ACLs), to provide rules that restrict what hosts on the network can and cannot do.
    * Endpoint containment
      * Disconnecting the infected system from any network connections (turning WiFi off, pulling ethernet cable).
        * Powering off the infected system.
        * Blocking rules in the local firewall.
        * Host intrusion prevention system (HIPS) actions, such as device isolation.
  * Eradication
    * Remove malicious artifacts
    * Reimage systems
  * Recovery
    * Identify root cause
    * Patch systems
    * Disable uneeded services
    * Update EDR, AV, IDPS, and SIEM rules
    * Share intelligence
  * Lessons Learned and Reporting
    * Post incident review meetings: what could be improved
    * Create report that should contain
      * Executive Summary
      * Incident Timeline
      * Incident Investigation
      * Appendix
      * Report considerations
        * Report Audience
        * Incident Investigation
        * Screenshots and Captions
