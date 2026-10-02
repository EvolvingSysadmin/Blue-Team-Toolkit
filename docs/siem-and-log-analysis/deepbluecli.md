# DeepBlueCLI

* Description: PowerShell module for threat hunting in Windows event logs
* Installation: download from <https://github.com/sans-blue-team/DeepBlueCLI>
  * If script execution is blocked, allow it for the current session only: `Set-ExecutionPolicy Bypass -Scope Process`
* Usage
  * Process the local Security log (PowerShell must be run as Administrator): `.\DeepBlue.ps1` or `.\DeepBlue.ps1 -log security`
  * Process the local System log: `.\DeepBlue.ps1 -log system`
  * Process an .evtx file: `.\DeepBlue.ps1 .\evtx\new-user-security.evtx`
  * Process all logs in a folder and output to text: `.\DeepBlue.ps1 .\evtx\* > output.txt`
* Resources
  * [DeepBlueCLI Repo](https://github.com/sans-blue-team/DeepBlueCLI)
  * [DeepBlueCLI Guide](https://www.socinvestigation.com/deepbluecli-powershell-module-for-threat-hunting/)
