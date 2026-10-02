# Splunk

* Description: SIEM and log analytics platform; searches are written in Search Processing Language (SPL)
* Installation: download from <https://www.splunk.com/en_us/products/splunk-enterprise.html>
* Usage
  * Starting Splunk on Linux
    * If not a service: `sudo /opt/splunk/bin/splunk start`
    * If running as a systemd service: `sudo systemctl start Splunkd`
  * Basic Search Queries
    * Source IP field (src) equals 10.10.10.50: `src="10.10.10.50"`
    * Destination IP field (dst) equals 10.10.100.5: `dst="10.10.100.5"`
    * 10.10.10.50 as either source or destination: `src="10.10.10.50" OR dst="10.10.10.50"`
    * Source 10.10.10.73 to any destination in 10.10.10.0/24: `src="10.10.10.73" dst="10.10.10.*"`
    * Simple failed login search: `pass* AND fail*`
    * Commands run by a process, in this case cmd.exe, from Sysmon logs: `index="botsv1" earliest=0 Image="*\\cmd.exe" | stats values(CommandLine) by host`
    * Newly created Windows users: `EventCode=4720` or search for `"net user" "/add"` in process command lines
    * Windows logons: `EventCode=4624`
    * Web scanners by user agent and headers: `index=index_name sourcetype=stream:http src_ip=xxx.xxx.xxx.xxx | stats count by src_headers | sort -count | head 3`
    * Search for .exe downloads: `index=botsv1 sourcetype=stream:http dest_ip="xxx.xxx.xxx.xxx" *.exe`
    * Results are returned newest first by default; to show oldest first: `| sort _time` (or `| reverse` to flip the current order)
  * Advanced SPL Examples (more can be found at <https://github.com/EvolvingSysadmin/Splunk-Tools>)
    * Search for credentials submitted to a form:

      ```SPL
      index=botsv1 sourcetype=stream:http dest_ip="xxx.xxx.xxx.xxx" http_method=POST form_data=*username*passwd*
        | rex field=form_data "passwd=(?<creds>\w+)"
        | table _time src_ip uri http_user_agent creds
      ```

    * Get metadata on the sourcetypes in an index:

      ```SPL
      | metadata type=sourcetypes index=botsv2
        | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S")
        | eval lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
        | eval recentTime=strftime(recentTime,"%Y-%m-%d %H:%M:%S")
        | sort - totalCount
      ```

    * List all values within a field (for example source):

      ```SPL
      index="botsv3"
        | top limit=0 source
      ```

    * Time spent crypto mining on a host (fss = flow start, fes = flow end):

      ```SPL
      index="botsv3" source="cisconvmflowdata" coinhive
        | stats min(fss) as starttime, max(fes) as endtime
        | eval timetaken = endtime-starttime
        | table timetaken
      ```

    * IAM access key of the account that generated the most distinct errors:

      ```SPL
      index="botsv3" sourcetype="aws:cloudtrail" user_type=IAMUser errorCode!=success eventSource="iam.amazonaws.com"
        | stats dc(errorMessage) as errors by userIdentity.accessKeyId
        | sort -errors
      ```

    * Port scanning: one source connecting to many destination ports (adjust index, sourcetype, and threshold to the data):

      ```SPL
      index=network sourcetype=firewall
        | stats dc(dest_port) as ports, values(dest_ip) as targets by src_ip
        | where ports > 100
        | sort -ports
      ```

* Resources
  * [Splunk Guide](https://github.com/EvolvingSysadmin/Splunk-Tools)
  * [Splunk Search Tutorial](https://docs.splunk.com/Documentation/Splunk/latest/SearchTutorial/WelcometotheSearchTutorial)
  * [Install Splunk Enterprise on Linux](https://docs.splunk.com/Documentation/Splunk/latest/Installation/InstallonLinux)
  * [Configure Splunk to start at boot time](https://docs.splunk.com/Documentation/Splunk/latest/Admin/ConfigureSplunktostartatboottime)
  * [Boss of the SOC (BOTS) datasets](https://github.com/splunk/botsv3)
  * [Install Splunk on Linux: Complete Setup Guide](https://www.inmotionhosting.com/support/security/install-splunk/)
  * [How to install Splunk on an Ubuntu desktop VM (VirtualBox)](https://www.youtube.com/watch?v=TW4l7X6G6Ak)
  * [Splunk Basic Search Video](https://www.youtube.com/watch?v=xtyH_6iMxwA)
