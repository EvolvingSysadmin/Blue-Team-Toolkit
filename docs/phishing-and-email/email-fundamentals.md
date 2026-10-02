# Email Fundamentals

Email protocols, sender authentication, common types of malicious email, and the artifacts to collect from a suspicious message.

## Why It Matters

Email is still the most common way into an organization, through credential phishing, malicious attachments, and business email compromise. Knowing how mail is sent and authenticated is what makes it possible to tell a spoofed message from a real one, and a lookalike domain from a compromised one.

## Reference

### Protocols

| Protocol | Ports | Use |
| :--- | :--- | :--- |
| SMTP | 25 | Server-to-server relay |
| SMTP submission | 587 (STARTTLS), 465 (implicit TLS) | Clients sending mail through a server |
| POP3 | 110, 995 (TLS) | Downloading mail to a client |
| IMAP | 143, 993 (TLS) | Syncing mail between server and client |

### Sender Authentication

| Standard | What It Does | Where It Lives |
| :--- | :--- | :--- |
| SPF (Sender Policy Framework) | Lists the servers allowed to send mail for a domain; receivers check the connecting server's IP against it | DNS TXT record on the domain |
| DKIM (DomainKeys Identified Mail) | The sending server signs the message; receivers verify the signature to confirm it was not altered and came from a server holding the domain's key | Public key in DNS at `<selector>._domainkey.<domain>` |
| DMARC | Tells receivers what to do when SPF and DKIM fail or do not align with the From domain (`none`, `quarantine`, `reject`) and where to send reports | DNS TXT record at `_dmarc.<domain>` |

### Types of Malicious Email

| Type | Goal |
| :--- | :--- |
| Credential phishing | Fake login pages reached by links, lookalike domains, shortened URLs, or QR codes |
| Malware delivery | Malicious attachments or links to download them |
| Business email compromise (BEC) | Impersonating executives or vendors to redirect payments or obtain data, often with no link or attachment |
| Spam recon | Checking whether addresses are valid from bounces and error codes |
| Social engineering recon | Getting a response to start a conversation |
| Tracking pixel recon | Confirming the email was opened, which can reveal the client, OS, IP address, and time |

### Spoofing Indicators

| Indicator | Where to Check |
| :--- | :--- |
| Display name or From address looks legitimate, but the sending IP belongs to an unrelated organization | `Received` headers, X-Originating-IP |
| Reply-To differs from From | Headers |
| SPF, DKIM, or DMARC failures | `Authentication-Results` header |
| Lookalike domain (for example `rn` in place of `m`) | From address, links |
| Branding copied from a known company | Message body |

### Artifacts to Collect

* Sending address and display name
* Subject line
* Recipients
* Date and time
* Sending server IP and its reverse DNS
* Reply-To (if present)
* URLs in the message: full URL, IP, and root domain
* Attachment file names and SHA256 hashes

### Common Malicious Attachment Types

| Category | Extensions |
| :--- | :--- |
| Executables and scripts | .exe, .scr, .vbs, .js, .bat, .ps1, .hta |
| Shortcuts | .lnk |
| Containers used to bypass Mark of the Web | .iso, .img, .zip, .rar, .7z |
| Office files with macros | .docm, .xlsm, older .doc and .xls |
| OneNote | .one |
| HTML and SVG | Used for HTML smuggling or local credential phishing pages |
| PDF | Embedded links or QR codes |

!!! warning "Analyze links and attachments in a sandbox"
    Do not open suspicious links or attachments on a work machine. Use a URL scanner or sandbox, and do not upload attachments that may contain company data to public services.

## How I Use It

When I look at a suspicious message, I check authentication first, because it narrows things down quickly: a message that passes SPF, DKIM, and DMARC for our own domain or a known partner points to a compromised account, not spoofing. Then I collect the artifacts above and check the URLs and hashes with the services below.

### Analysis Services

| Purpose | Service |
| :--- | :--- |
| Domain and IP lookup | [DomainTools Whois](https://whois.domaintools.com/), [ICANN Lookup](https://lookup.icann.org/en) |
| URL scanning | [urlscan.io](https://urlscan.io/), [URLhaus](https://urlhaus.abuse.ch/) |
| Raw HTTP response | [Wannabrowser](https://www.wannabrowser.net/) |
| Reverse IP and geolocation | [MXToolbox Reverse Lookup](https://mxtoolbox.com/ReverseLookup.aspx), [IPLocation](https://www.iplocation.net/) |
| Reported phishing | [PhishTank](https://phishtank.org/) |
| File reputation and sandboxing | [VirusTotal](https://www.virustotal.com/gui/home/upload), [Talos File Reputation](https://talosintelligence.com/talos_file_reputation), [Hybrid Analysis](https://www.hybrid-analysis.com/) |

## Related

* [Email Headers](email-headers.md)
* [Phishing](../playbooks/incident-response/phishing.md) playbook
* [Compromised Account / BEC](../playbooks/incident-response/bec.md) playbook

## Resources

* [DMARC.org](https://dmarc.org/)
* [M3AAWG Email Authentication Best Practices](https://www.m3aawg.org/)
