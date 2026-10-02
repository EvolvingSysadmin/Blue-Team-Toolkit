# Evidence Handling

* Digital Evidence Process: Identification -> Preservation -> Collection -> Analysis -> Reporting
* Forms of Digital Evidence
  * Email
  * Digital photographs
  * Logs
  * Documents
  * Messages
  * Files
  * Browser history
  * Databases
  * Backups
  * Disk images
  * Memory images
  * Video/audio files
* Evidence Handling Tenets
  * Do not alter original evidence; work from verified copies
  * Use write-blockers when imaging storage media
  * Document every step: who, what, when, where, and how
* Order of Volatility (RFC 3227): collect the most volatile data first
  * CPU registers and cache
  * Routing table, ARP cache, process table, kernel statistics, memory
  * Temporary file systems
  * Disk
  * Remote logging and monitoring data
  * Physical configuration and network topology
  * Archival media
* Chain of Custody
  * Hash evidence at collection and verify the hash before analysis
  * Take a forensic copy and analyze the copy
  * Store evidence securely with controlled access
  * Record every transfer on a chain of custody form
* Resources
  * [RFC 3227: Guidelines for Evidence Collection and Archiving](https://datatracker.ietf.org/doc/html/rfc3227)
  * [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)
