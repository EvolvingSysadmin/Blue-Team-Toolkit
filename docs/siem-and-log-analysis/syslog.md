
* Description: standard protocol used to convey event or system log notification messages to a designated server, known as a Syslog server
  * Syslog protocol can be enabled on most network devices
  * Uses UDP 514 by default, TCP 514 for more reliability, TCP 6514 for stricter security standards
* Syslog messages made of three components:
  * Priority Value (PRI): consists of Facility Code and Severity Level tables
  * Header: contains identifying information, such as; Timestamp, Hostname, Application name, Message ID
  * Message: usually saved in a file in /var/log
* Resources
  * [How Does Syslog Work](https://www.auvik.com/franklyit/blog/what-is-syslog/)
