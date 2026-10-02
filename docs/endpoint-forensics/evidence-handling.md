# Evidence Handling

Collecting digital evidence in an order and a way that keeps it intact and defensible.

## Why It Matters

Evidence that was altered, collected in the wrong order, or cannot be accounted for is less useful to the investigation and may be unusable if the incident ends up in court, with an insurer, or with a regulator. Volatile data such as memory is also gone the moment a system is shut down.

## Reference

### Digital Evidence Process

Identification -> Preservation -> Collection -> Analysis -> Reporting

### Forms of Digital Evidence

| Category | Examples |
| :--- | :--- |
| Volatile | Memory images, running processes, network connections |
| System | Disk images, logs, registry, browser history |
| User data | Documents, email, messages, photos, audio and video |
| Business systems | Databases, backups, cloud audit logs |

### Order of Volatility

From [RFC 3227](https://datatracker.ietf.org/doc/html/rfc3227): collect the most volatile data first.

| Order | Data |
| :--- | :--- |
| 1 | CPU registers and cache |
| 2 | Routing table, ARP cache, process table, kernel statistics, memory |
| 3 | Temporary file systems |
| 4 | Disk |
| 5 | Remote logging and monitoring data |
| 6 | Physical configuration and network topology |
| 7 | Archival media |

### Handling Principles

| Principle | Practice |
| :--- | :--- |
| Do not alter the original | Analyze verified copies; use write-blockers when imaging storage media |
| Prove integrity | Hash evidence at collection and verify the hash before analysis |
| Document everything | Who collected what, when, where, how, and with which tool |
| Control access | Store evidence securely and record every transfer on a chain of custody form |

## How I Use It

In practice, most of my evidence collection is remote: EDR live response, triage collections, and log exports. The same principles apply. I hash what I collect, note the time and the tool, keep the original collection untouched, and work from copies. When memory might matter, I capture it before anything that could change the system, including isolation.

## Related

* [Memory Artifacts](memory-artifacts.md)
* [File Hashing](file-hashing.md)
* [FTK Imager](tools/ftk-imager.md), [KAPE](tools/kape.md)
* [Endpoint Malware](../playbooks/incident-response/endpoint-malware.md) playbook

## Resources

* [RFC 3227: Guidelines for Evidence Collection and Archiving](https://datatracker.ietf.org/doc/html/rfc3227)
* [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)
