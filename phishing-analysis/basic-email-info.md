# Basic Email Info

* Email Protocols
  * Simple Mail Transfer Protocol (SMTP): Port 25 by default, Port 587 for TLS
  * Post Office Protocol 3 (POP3): Port 110 by default, Port 995 for TLS
  * Internet Mail Access Protocol (IMAP): Port 143 by default, Port 993 for TLS
* Email Security Measures
  * Sender Policy Framework (SPF): a type of DNS (TXT) record that can help prevent an email address from being forged by sending alerts
  * Domain Keys Identified Mail (DKIM): cryptographically verifies if an email has been sent by its trusted servers and wasn't tampered during transmission
  * Domain-based Message Authentication, Reporting and Conformance (DMARC): email authentication, policy and reporting protocol that specifies what happens upon SPF and DKIM failure
* Types of Malicious Emails
  * Spam Recon Emails: identifying if email error codes are sent back
  * Social Engineering Recon Emails: attempting to get response
  * Tracking Pixel Recon Emails: see if the email has been viewed by an email client (track OS, email website, client, screen resolution, date/time of read, IP address)
  * Spam email
  * Links to credential harvesters, domains with typo squatting, shortened urls
* Email Spoofing
  * From address may look legitimate but whois lookup of X-Originating-IP shows different organization
  * Reply-To address may be different than sender address
  * HTML styling
* Common Email Artifacts
  * Sending Address
  * Subject Line
  * Recipient(s)
  * Date and Time
  * Sending Server IP
  * Reverse DNS of Sending Server IP
  * Reply-To (if present)
  * Links/a hrefs (IP and root domain of those links)
  * File Attachment name
  * File attachment SHA256 HASH
* Common Malicious Email Attachment File Types
  * .exe (Executable)
  * .vbs (Visual Basic Script)
  * .js (JavaScript)
  * .iso (Optical Disk Image)
  * .bat (Windows Batch File)
  * .ps/.ps1 (PowerShell Scripts)
  * .htm/.html (Web Pages / Hypertext Markup Language)
* Email anslysis resources
  * Domain/IP Lookup: <https://whois.domaintools.com/>
  * Domain Registration Lookup: <https://lookup.icann.org/en>
  * URL Analysis: <https://urlhaus.abuse.ch/>
  * Show root HTTP Response: <https://www.wannabrowser.net/>
  * Reverse IP Lookup: <https://mxtoolbox.com/ReverseLookup.aspx>
  * IP Geolocation: <https://www.iplocation.net/>
  * URL Sandbox: <https://urlscan.io/>
  * Track reported phishing data: <https://phishtank.org/>
  * Virustotal Malware Analysis: <https://www.virustotal.com/gui/home/upload>
  * Talos Malware Analysis: <https://talosintelligence.com/talos_file_reputation>
  * Hybrid Analysis Malware Analysis: <https://www.hybrid-analysis.com/>
