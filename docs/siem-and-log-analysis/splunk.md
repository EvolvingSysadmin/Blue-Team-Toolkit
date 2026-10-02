# Splunk

* Description: SIEM and log analytics platform; searches are written in Search Processing Language (SPL)
* Installation: download Splunk Enterprise from <https://www.splunk.com/en_us/products/splunk-enterprise.html>; the free license covers a limited daily ingest volume, which is enough for a home lab
* Starting Splunk on Linux
  * If not a service: `sudo /opt/splunk/bin/splunk start`
  * If running as a systemd service: `sudo systemctl start Splunkd`
  * Start at boot: `sudo /opt/splunk/bin/splunk enable boot-start -systemd-managed 1`
* Web interface: `http://<server>:8000`
* Getting data in
  * Forward Windows and Linux logs with the Universal Forwarder
  * Receive syslog from network devices on a dedicated input or through a syslog server that writes to files Splunk monitors
  * Practice data: the [Boss of the SOC (BOTS)](https://github.com/splunk/botsv3) datasets
* Search basics
  * Always set an index and a time range; searching everything is slow
  * Results are returned newest first by default
  * Pipe searches into commands like `stats`, `table`, `sort`, and `rex` to summarize and extract fields
* SPL queries: my SPL searches and Splunk notes are in a separate repo: [Splunk-Tools](https://github.com/EvolvingSysadmin/Splunk-Tools)
* Resources
  * [Splunk Search Tutorial](https://docs.splunk.com/Documentation/Splunk/latest/SearchTutorial/WelcometotheSearchTutorial)
  * [Install Splunk Enterprise on Linux](https://docs.splunk.com/Documentation/Splunk/latest/Installation/InstallonLinux)
  * [Configure Splunk to start at boot time](https://docs.splunk.com/Documentation/Splunk/latest/Admin/ConfigureSplunktostartatboottime)
  * [Splunk Universal Forwarder](https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/Abouttheuniversalforwarder)
