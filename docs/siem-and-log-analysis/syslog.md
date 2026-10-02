# Syslog

The standard protocol for sending log messages from devices and systems to a central server.

## Why It Matters

Most network devices, Linux systems, and appliances send their logs with syslog. Getting those logs off the device and onto a central server or SIEM is what makes them available, and trustworthy, during an investigation.

## Reference

### Protocol

| Item | Details |
| :--- | :--- |
| Standard | [RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424) (older devices use the BSD format, RFC 3164) |
| UDP 514 | Default; no delivery guarantee |
| TCP 514 | Commonly used for reliable delivery |
| TCP 6514 | Syslog over TLS ([RFC 5425](https://datatracker.ietf.org/doc/html/rfc5425)) |

### Message Format

| Part | Contents |
| :--- | :--- |
| Priority (PRI) | Calculated from the facility and the severity |
| Header | Timestamp, hostname, application name, process ID, message ID |
| Message | The event text |

### Severity Levels

| Level | Name |
| :--- | :--- |
| 0 | Emergency |
| 1 | Alert |
| 2 | Critical |
| 3 | Error |
| 4 | Warning |
| 5 | Notice |
| 6 | Informational |
| 7 | Debug |

## How I Use It

On Linux, rsyslog or syslog-ng receives messages and writes them to files under `/var/log`, or forwards them on to the SIEM. When I set up a new device, I send its logs to the collector and check that they arrive with correct timestamps and hostnames, because a device that has been quietly failing to log is only discovered when its logs are needed.

## Related

* [Network Device Logs](network-device-logs.md)
* [Linux Logs](linux-logs.md)

## Resources

* [How Does Syslog Work](https://www.auvik.com/franklyit/blog/what-is-syslog/)
* [RFC 5424: The Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424)
