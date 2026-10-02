# Syslog

* Description: standard protocol for sending event and system log messages to a central server, known as a syslog server or collector (RFC 5424)
  * Syslog can be enabled on most network devices, Linux systems, and many appliances
  * Ports: UDP 514 by default; TCP 514 is commonly used for reliable delivery; TCP 6514 for syslog over TLS (RFC 5425)
* Syslog messages are made of three components:
  * Priority Value (PRI): calculated from the Facility code and the Severity level (0 Emergency through 7 Debug)
  * Header: identifying information such as timestamp, hostname, application name, and message ID
  * Message: the event text itself
* On Linux, rsyslog or syslog-ng writes received messages to files under `/var/log`
* Resources
  * [How Does Syslog Work](https://www.auvik.com/franklyit/blog/what-is-syslog/)
  * [RFC 5424: The Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424)
