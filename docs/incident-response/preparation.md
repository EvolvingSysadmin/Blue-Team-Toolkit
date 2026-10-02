# Preparation

* Create an incident response plan
  * Define scope, roles and responsibilities, severity levels, escalation paths, and communication requirements (internal, legal, regulators, customers)
  * Cover each phase of the lifecycle: preparation, detection and analysis, containment, eradication, recovery, and post-incident activity
  * Example incident response plans
    * [Carnegie Mellon University](https://www.cmu.edu/iso/governance/procedures/docs/incidentresponseplan1.0.pdf)
    * [Wright State University](https://www.wright.edu/information-technology/policies)
* Build the incident response team
  * Conduct training and tabletop exercises
  * Write playbooks for common incident types (phishing, compromised account, malware, ransomware)
  * [Microsoft incident response playbooks](https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks)
  * [CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks](https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks)
* Maintain asset inventories, network diagrams, and a list of critical systems and data owners
* Run risk assessments
* Confirm logging coverage and retention before an incident, not during one
* Put defensive controls in place, for example:
  * Network: firewalls, DMZ, network segmentation, NIDS/NIPS, web proxies, NAC
  * Endpoint: EDR, antivirus, host firewalls, application allowlisting, GPO baselines
  * Email: SPF/DKIM/DMARC, external sender tagging, spam and attachment filtering, sandboxing
  * Data: DLP, backups (including offline or immutable copies), encryption
  * Monitoring: centralized logging and SIEM
  * People: awareness training and phishing simulations
  * Physical security
