# Email Headers

The header fields that matter when tracing a message and checking whether it is what it claims to be.

## Why It Matters

The parts of an email a user sees (display name, From address, subject) are easy to fake. The headers record which servers actually handled the message and whether it passed authentication, which is where spoofing and lookalike domains get caught.

## Reference

### Core Headers

| Header | Contents | Notes |
| :--- | :--- | :--- |
| From | The author's address, as shown to the recipient | Required (RFC 5322); easy to spoof |
| Date | When the message was written or sent | Required (RFC 5322) |
| To, Cc | Recipients | |
| Subject | Message subject | |
| Message-ID | Unique ID from the sending system | Use it to search mail logs and message traces |
| Reply-To | Where replies go | Differs from From in many phishing emails |
| Return-Path | Bounce address (envelope sender) | The domain SPF is checked against |
| Received | Added by each server that handled the message | Read from the bottom up; the lowest is closest to the sender |
| Delivered-To | The mailbox the message was delivered to | |
| Content-Type | Message format | `multipart/mixed` usually means attachments |

### Authentication Headers

| Header | Contents |
| :--- | :--- |
| Received-SPF | SPF result for the sending IP |
| DKIM-Signature | The signature, signing domain (`d=`), and selector (`s=`) used to look up the public key in DNS |
| Authentication-Results | SPF, DKIM, and DMARC results recorded by the receiving server |

### Custom X-Headers

Non-standard headers added by mail providers and security tools, such as X-Originating-IP, X-Mailer, and spam filter verdicts like X-MS-Exchange-Organization-SCL.

## How I Use It

I always work from the original message, saved as an .eml or .msg file or pulled from the mail security portal, because forwarding a message replaces its headers. Then I paste the headers into an analyzer to get a readable hop-by-hop view, and check three things: the authentication results, whether From, Reply-To, and Return-Path agree, and where the bottom-most `Received` header says the message really came from.

### Header Analyzers

* [Microsoft Message Header Analyzer](https://mha.azurewebsites.net/)
* [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
* [Google Admin Toolbox Messageheader](https://toolbox.googleapps.com/apps/messageheader/)

## Related

* [Email Fundamentals](email-fundamentals.md)
* [Phishing](../playbooks/incident-response/phishing.md) playbook

## Resources

* [IANA Message Headers List](https://www.iana.org/assignments/message-headers/message-headers.xhtml)
* [Email Header Quick Reference Guide](https://jkorpela.fi/headers.html)
* [Email headers: What they are and how to read them](https://www.mailjet.com/blog/deliverability/how-to-read-email-headers/)
* [Email Header Analysis and its application in Email Forensics](https://www.stellarinfo.com/article/email-header-structure-forensic-analysis.php)
