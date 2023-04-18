# Splunk

* Description: SIEM with advanced functionality
* Installation: download from <https://www.splunk.com/en_us/products/splunk-enterprise.html>
* Usage
  * Starting Splunk on Linux
    * If not a service: `sudo /opt/splunk/bin/splunk start`
    * If running as a service: `sudo systemctl start Splunkd`
  * Basic Search Queries
    * Search source IP field (src) and the IP address value 10.10.10.50: `search src="10.10.10.50"`
    * Search desttination IP field (dst): `search dst="10.10.100.5"`
    * Search source IP field (src) and destination IP field (dst) the IP address value 10.10.10.50: `search src="10.10.10.50" OR dst="10.10.10.50"`
    * Search source IP field (src) to any destination IP field (dst) on the 10.10.10.0/24: `search src="10.10.10.73" dst="10.10.10.*"`
    * Simple failed login failure search: `search pass* AND fail*`
    * Show executables denerated from process, in this case cmd.exe, from Sysmon logs: `index="botsv1" earliest=0 Image="*\\cmd.exe" | stats values(CommandLine) by host`
    * Search for newly created windows user: search eventID field for 4270 or "net user"
    * Search for windows user logins: search eventID field for 4624
    * To search for web scanners: `index=index_name sourcetype=stream:http src_ip=xxx.xxx.xxx.xxx | stats count by src_headers | sort -count | head 3`
    * Search for .exe: `index=botsv1 sourcetype=stream:http dest_ip="xxx.xxx.xxx.xxx" *.exe`
    * To display search results in reverse chronological order: `| reverse`
  * Resources
    * [Splunk Guide](https://github.com/EvolvingSysadmin/Splunk-Tools)
    * [Basic Splunk Searches](https://docs.splunk.com/Documentation/Splunk/9.0.1/SearchTutorial/Startsearching)
    * [Install Splunk on Linux](https://docs.splunk.com/Documentation/SplunkLight/7.3.6/Installation/InstallonLinux)
    * [Install Splunk on Linux – Complete Setup Guide](https://www.inmotionhosting.com/support/security/install-splunk/)
    * [How to install Splunk on an Ubuntu desktop VM (Virtual Box)](https://www.youtube.com/watch?v=TW4l7X6G6Ak)
    * [Splunk Automatically Start upon Boot](https://docs.splunk.com/Documentation/Splunk/9.0.1/Admin/ConfigureSplunktostartatboottime)
    * [Splunk Basic Search Video](https://www.youtube.com/watch?v=xtyH_6iMxwA)
  * Advanced SPL Examples (more can be found at <https://github.com/EvolvingSysadmin/Splunk-Tools>)
    * Search for credentials submitted to form:

      ```SPL
      index=botsv1 sourcetype=stream:http dest_ip="xxx.xxx.xxx.xxx" http_method=POST form_data=*username*passwd* 
        | rex field=form_data "passwd=(?<creds>\w+)" 
        | table _time src_ip uri http_user_agent creds
      ```

    * To get metadata information on sourcetypes or other fields in an index:

      ```SPL
        | metadata type=sourcetypes index=botsv2 
        | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S") 
        | eval lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S") 
        | eval recentTime=strftime(recentTime,"%Y-%m-%d %H:%M:%S") 
        | sort - totalCount
      ```

    * List all values within a field (eg sourcetype or source):

      ```SPL
      index="botsv3"
        | top limit=* source
        | sort - count
      ```

    * Time of crypto mining on host (fss = mining start fes = mining stop)

      ```SPL
      index="botsv3" source="cisconvmflowdata" coinhive
        | stats min(fss) as starttime, max(fes) as endtime
        | eval timetaken = endtime-starttime
        | table timetaken
      ```

    * Search for IAM key of account that generated most distinct errors:

      ```SPL
      index="botsv3" sourcetype="aws:cloudtrail" user_type=IAMUser errorCode!=success eventSource="iam.amazonaws.com"
        | stats dc(errorMessage) as errors by userIdentity.accessKeyId
        | sort -errors
      ```

    * To detect syn scanning:

      ```SPL
      index="botsv3" tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024

      ```
