# Windows Log Analysis

* Description: Windows event IDs that help in log analysis. Most events are in the Security log, many only logged on Domain Controller
  * “Windows Event logs” or “Event Logs” are files in binary format (with .evtx extension), stored here:
    * Windows 2000 to WinXP/Windows Server 2003: `%WinDir%\system32\Config*.evt`
    * Windows Server 2008 to 2019, and Windows Vista to Win10: `%WinDir%\system32\WinEVT\Logs*.evtx`
* Event Log Categories
  * Application: Events logged by an application (Execution, Deployment error, etc.)
  * System: Events logged by the Operating System (Device loading, startup errors, etc.)
  * Security: Events that are relevant to the security of the system (Logins and logouts, file deletion, granting of administration permissions, etc.)
  * Directory Service: This is a record available only to Domain Controllers, it stores Active Directory (AD) events
  * DNS Server: It is a record available only to DNS servers; logs of DNS service are stored
  * File Replication Service: Is a record available only for Domain Controllers, it stores Domain Controller Replication events
* Events
  * User logon/logoff
    * Successful logon: 528, 540, 4624, 5379
    * Failed logon: 529-537, 539, 4625
    * Logoff: 538, 551, 4672, 4634, 4647
    * Special Logon: 4672
    * Logon attempt with explicit credentials: 4648
    * Replay attack detected: 4649
  * User account changes
    * Created 624, 4720
    * Enabled 626
    * Changed 642
    * Disabled 629
    * Deleted 630. 4726
    * Memeber added to security enabled group: 4732
  * Password changes
    * To self: 628
    * To others: 627
    * Password reset: 4724
  * File access events
    * A handle to an object was requested with intent to delete: 4659
    * A handle to an object was requested: 4656
    * The handle to an object was closed: 4658
    * An object was deleted: 4660
    * An attempt was made to access an object: 4663
    * The state of a transaction has changed: 4685
    * The state of a transaction has changed: 4985
  * Anamolous events
    * Service started or stopped: 7035, 7036
    * Object access denied (if auditing enabled): 560, 567
    * High number of deleted files: 4663
    * Changes to user rights assignments: 4704, 4717
    * Altered Audit and Account policies: 4719, 4739
    * Security log cleared: 1102
    * Reboot: 1074
    * SIDs filtered: 4675
    * New domain trust: 4706
* Resources
  * [Detecting a Security Threat in Event Logs](https://blog.netwrix.com/2014/12/03/detecting-a-security-threat-in-event-logs/)
  * [Windows Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j)
  * [Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
  * [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
  * [Windows security auditing — Event Log FAQ](https://eventlogxp.com/essentials/securityauditing.html)
  * [Windows Security Event Logs: my own cheatsheet](https://andreafortuna.org/2019/06/12/windows-security-event-logs-my-own-cheatsheet/)
  * [Common Windows IDs for SOC](https://www.socinvestigation.com/most-common-windows-event-ids-to-hunt-mind-map/)
  * [MyEventLog](https://www.myeventlog.com/)
  * [Github Eventlog Database](https://github.com/stuhli/awesome-event-ids#event-id-databases)
