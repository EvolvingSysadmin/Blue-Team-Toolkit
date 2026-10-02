# Email Headers

* Required Headers (RFC 5322)
  * From: the author's address, as shown to the recipient; easy to spoof
  * Date: when the message was written or sent
* Common Headers
  * To, Cc: recipients
  * Subject: the message subject
  * Message-ID: unique identifier assigned by the sending system; useful for searching mail logs and message traces
  * Reply-To: address replies go to; a Reply-To that differs from From is a common phishing indicator
  * Return-Path: address bounces go to (the envelope sender); used for the SPF check
  * Received: added by each server that handles the message; read from the bottom up, so the lowest Received header is closest to the sender
  * Delivered-To: the mailbox the message was finally delivered to
  * Content-Type: the format of the message (text/plain, text/html, multipart/mixed for attachments)
* Authentication Headers
  * Received-SPF: SPF result for the sending IP
  * DKIM-Signature: the DKIM signature, including the signing domain (`d=`) and selector (`s=`) used to look up the public key in DNS
  * Authentication-Results: SPF, DKIM, and DMARC results recorded by the receiving server
* Custom X-Headers
  * Non-standard headers added by mail providers and security tools, for example X-Originating-IP, X-Mailer, and spam filter verdicts such as X-MS-Exchange-Organization-SCL
* Header Analysis Tools
  * [Microsoft Message Header Analyzer](https://mha.azurewebsites.net/)
  * [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
  * [Google Admin Toolbox Messageheader](https://toolbox.googleapps.com/apps/messageheader/)
* Header Lists/Guides
  * [IANA Message Headers List](https://www.iana.org/assignments/message-headers/message-headers.xhtml)
  * [Email Header Quick Reference Guide](https://jkorpela.fi/headers.html)
  * [Email Header Guide](https://mailtrap.io/blog/email-headers/)
  * [Email headers: What they are & how to read them](https://www.mailjet.com/blog/deliverability/how-to-read-email-headers/)
  * [Email Header Analysis and its application in Email Forensics](https://www.stellarinfo.com/article/email-header-structure-forensic-analysis.php)
