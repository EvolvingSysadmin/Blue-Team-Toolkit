# DeepBlueCLI

PowerShell module from SANS for threat hunting in Windows event logs.

## When I Use It

* Quick triage of event logs from a single host or a set of exported .evtx files, with no SIEM involved
* A first pass that flags suspicious events (new accounts, log clearing, password spraying, suspicious command lines) before reviewing logs by hand

## Installation

* Download or clone from <https://github.com/sans-blue-team/DeepBlueCLI>
* If script execution is blocked, allow it for the current session only: `Set-ExecutionPolicy Bypass -Scope Process`

## Common Tasks

| Task | Command |
| :--- | :--- |
| Process the local Security log (run as Administrator) | `.\DeepBlue.ps1` or `.\DeepBlue.ps1 -log security` |
| Process the local System log | `.\DeepBlue.ps1 -log system` |
| Process an exported .evtx file | `.\DeepBlue.ps1 .\evtx\new-user-security.evtx` |
| Process a folder of logs and save the output | `.\DeepBlue.ps1 .\evtx\* > output.txt` |

## Reading the Output

* Each finding includes a message explaining what was detected, the command line or account involved, and a decoded version of obfuscated commands where possible
* Findings are leads, not verdicts; I confirm each one against the raw events in [Windows Event Logs](windows-event-logs.md)

## Related

* [Windows Event Logs](windows-event-logs.md)
* [Suspicious PowerShell](../playbooks/alert-triage/suspicious-powershell.md) runbook

## Resources

* [DeepBlueCLI Repo](https://github.com/sans-blue-team/DeepBlueCLI)
* [DeepBlueCLI Guide](https://www.socinvestigation.com/deepbluecli-powershell-module-for-threat-hunting/)
