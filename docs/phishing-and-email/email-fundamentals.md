# Email Fundamentals

* Email Protocols
  * Simple Mail Transfer Protocol (SMTP): port 25 for server-to-server relay; port 587 for client submission with STARTTLS; port 465 for submission over implicit TLS
  * Post Office Protocol 3 (POP3): port 110, or 995 for POP3 over TLS
  * Internet Message Access Protocol (IMAP): port 143, or 993 for IMAP over TLS
* Email Authentication
  * Sender Policy Framework (SPF): a DNS TXT record listing the servers allowed to send mail for a domain; receivers check the connecting server's IP against it
  * DomainKeys Identified Mail (DKIM): the sending server signs the message; receivers verify the signature with a public key published in DNS, proving the message was not altered and was sent by a server holding the domain's key
  * Domain-based Message Authentication, Reporting and Conformance (DMARC): a DNS policy that tells receivers what to do when SPF and DKIM fail or do not align with the From domain (`none`, `quarantine`, `reject`) and where to send reports
* Types of Malicious Emails
  * Spam recon emails: checking whether an address is valid based on bounces and error codes
  * Social engineering recon emails: trying to get a response
  * Tracking pixel recon emails: confirming the email was opened (can reveal OS, email client, IP address, and time opened)
  * Spam
  * Credential harvesting: links to fake login pages, typosquatted domains, shortened URLs, QR codes
  * Malware delivery: malicious attachments or links to download them
  * Business email compromise (BEC): impersonation of executives or vendors to redirect payments or obtain data, often with no link or attachment
* Email Spoofing Indicators
  * Display name or From address looks legitimate, but the sending IP or X-Originating-IP belongs to an unrelated organization
  * Reply-To address differs from the From address
  * SPF, DKIM, or DMARC failures in the Authentication-Results header
  * Lookalike domains (for example `rn` in place of `m`)
  * HTML styling that copies a known brand
* Common Email Artifacts to Collect
  * Sending address
  * Subject line
  * Recipient(s)
  * Date and time
  * Sending server IP
  * Reverse DNS of sending server IP
  * Reply-To (if present)
  * URLs in the message (full URL, IP, and root domain)
  * Attachment file name
  * Attachment SHA256 hash
* Common Malicious Attachment Types
  * Executables and scripts: .exe, .scr, .vbs, .js, .bat, .ps1, .hta
  * Shortcuts: .lnk
  * Containers used to bypass Mark of the Web: .iso, .img, .zip, .rar, .7z
  * Office files with macros: .docm, .xlsm, and older .doc and .xls
  * OneNote files: .one
  * HTML and SVG files, often used for HTML smuggling or credential phishing pages
  * PDF files with embedded links or QR codes
* Email Analysis Resources
  * Domain/IP lookup: <https://whois.domaintools.com/>
  * Domain registration lookup: <https://lookup.icann.org/en>
  * URL analysis: <https://urlhaus.abuse.ch/>
  * Show raw HTTP response: <https://www.wannabrowser.net/>
  * Reverse IP lookup: <https://mxtoolbox.com/ReverseLookup.aspx>
  * IP geolocation: <https://www.iplocation.net/>
  * URL sandbox: <https://urlscan.io/>
  * Reported phishing data: <https://phishtank.org/>
  * VirusTotal: <https://www.virustotal.com/gui/home/upload>
  * Talos file reputation: <https://talosintelligence.com/talos_file_reputation>
  * Hybrid Analysis: <https://www.hybrid-analysis.com/>
