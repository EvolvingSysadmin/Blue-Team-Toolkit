# DeepBlueCLI

* Description: PowerShell Module for Threat Hunting via Windows Event Log
* Installation: download from <https://github.com/sans-blue-team/DeepBlueCLI>
  * May have to bypass remote code executioin on system: `Set-ExecutionPolicy Bypass -Scope CurrentUser`
* Usage
  * Process local Windows security event log (PowerShell must be run as Administrator): `.\DeepBlue.ps1` or `.\DeepBlue.ps1 -log security`
  * Process local Windows system event log: `.\DeepBlue.ps1 -log system`
  * Process evtx File: `.\DeepBlue.ps1 .\evtx\new-user-security.evtx`
  * Process all logs and output to txt: `./DeepBlue.ps1 .\evtx\* > output.txt`
* Resources
  * [DeepBlueCLI Repo](https://github.com/sans-blue-team/DeepBlueCLI)
  * [DeepBlieCLI Guide](https://www.socinvestigation.com/deepbluecli-powershell-module-for-threat-hunting/)
