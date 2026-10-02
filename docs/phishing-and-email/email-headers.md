# Email Headers

* Standard Headers
  * From, showing the sender's email address
  * To, showing the recipient's email address
  * Date, showing the date when the email was sent.
* Optional Headers
  * Received, showing various information about the intermediary servers and the date when the message was processed
  * Reply-To, showing a reply address
  * Delivered-To displays the recipient’s name and address, as well as other addresses present in the CC and BCC
  * From: IP address/other details about sender
  * subject showing the message's subject
  * message-ID, showing a unique identification for the message
  * message body, containing the message, separated from the header by a line break
  * Return-Path: return address in case of email failure
  * Content-Type field indicates whether the format of an email was HTML, TXT, or any other option
  * Received-SPF: sender verification
  * Authentication-Results: ID of authentication performing server
  * DKIM Signature: details of the sender, message, and the public key which is required to perform message authentication
* Custom X-Headers
  * X-Received: non-standard headers added by some email providers
* Header Lists/Guides
  * [IANA Email Message Headers List](https://www.iana.org/assignments/message-headers/message-headers.xhtml)
  * [Email Header Quick Reference Guide](https://jkorpela.fi/headers.html)
  * [Email Header Guide](https://mailtrap.io/blog/email-headers/)
  * [Email headers: What they are & how to read them](https://www.mailjet.com/blog/deliverability/how-to-read-email-headers/)
  * [Email Header Analysis and its application in Email Forensics](https://www.stellarinfo.com/article/email-header-structure-forensic-analysis.php)
  