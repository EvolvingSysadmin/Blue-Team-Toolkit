# Sysmon

* Description: Sysinternals system service and driver that stays resident across reboots and logs detailed process, network, file, and registry activity to the Windows event log
* Installation: download from <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>
* Usage
  * Install with a configuration file (run as administrator): `sysmon64.exe -accepteula -i sysmonconfig.xml`
  * Update the configuration on a running install: `sysmon64.exe -c sysmonconfig.xml`
  * Events are written to Event Viewer under Applications and Services Logs > Microsoft > Windows > Sysmon > Operational
* Key Event IDs
  * 1: process creation (with command line and hashes)
  * 3: network connection
  * 7: image loaded (DLL)
  * 8: CreateRemoteThread (common in process injection)
  * 10: process access (for example access to `lsass.exe`)
  * 11: file created
  * 12, 13, 14: registry object created/deleted, value set, key renamed
  * 22: DNS query
* Resources
  * [Sysmon Configuration File (SwiftOnSecurity)](https://github.com/SwiftOnSecurity/sysmon-config)
  * [sysmon-modular (Olaf Hartong)](https://github.com/olafhartong/sysmon-modular)
  * [Install and use Sysmon for malware investigation](https://support.sophos.com/support/s/article/KB-000038882?language=en_US)
