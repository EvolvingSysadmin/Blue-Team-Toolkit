# Splunk

SIEM and log analytics platform; searches are written in Search Processing Language (SPL).

## When I Use It

* Centralizing and searching logs from many sources during an investigation
* Building alerts and dashboards for recurring detections
* Practicing investigations with the Boss of the SOC datasets

My SPL searches and Splunk notes are in a separate repo: [Splunk-Tools](https://github.com/EvolvingSysadmin/Splunk-Tools).

## Installation

* Download Splunk Enterprise from <https://www.splunk.com/en_us/products/splunk-enterprise.html>; the free license covers a limited daily ingest volume, which is enough for a home lab
* Start on Linux: `sudo /opt/splunk/bin/splunk start`
* Start as a systemd service: `sudo systemctl start Splunkd`
* Start at boot: `sudo /opt/splunk/bin/splunk enable boot-start -systemd-managed 1`
* Web interface: `http://<server>:8000`

## Common Tasks

| Task | How |
| :--- | :--- |
| Collect Windows and Linux logs | Install the Universal Forwarder on each host |
| Collect network device logs | A dedicated syslog input, or a syslog server writing files that Splunk monitors |
| Get practice data | [Boss of the SOC (BOTS)](https://github.com/splunk/botsv3) datasets |
| Search | Set an index and a time range, then pipe results into commands like `stats`, `table`, `sort`, and `rex` |

## Reading the Output

* Results are returned newest first by default
* Searches without an index and a time range are slow and can miss data in other indexes
* Field names depend on the add-on that parsed the data, so the same value can be `src`, `src_ip`, or `SourceIP` in different sources

## Related

* [Splunk-Tools](https://github.com/EvolvingSysadmin/Splunk-Tools) repo
* [Log Review Approach](log-review-approach.md)

## Resources

* [Splunk Search Tutorial](https://docs.splunk.com/Documentation/Splunk/latest/SearchTutorial/WelcometotheSearchTutorial)
* [Install Splunk Enterprise on Linux](https://docs.splunk.com/Documentation/Splunk/latest/Installation/InstallonLinux)
* [Configure Splunk to start at boot time](https://docs.splunk.com/Documentation/Splunk/latest/Admin/ConfigureSplunktostartatboottime)
* [Splunk Universal Forwarder](https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/Abouttheuniversalforwarder)
