# KAPE

Kroll Artifact Parser and Extractor: collects forensic artifacts from a live system or mounted image and parses them, usually in minutes.

## When I Use It

* Fast triage collection from a Windows host instead of a full disk image
* Collecting the same artifact set consistently across several hosts
* Parsing the collection straight to CSV with Eric Zimmerman's tools

## Installation

* Download from <https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape>
* Runs without installation; keep Targets and Modules updated with `kape.exe --sync`

## Common Tasks

KAPE has two parts: **Targets** collect files, and **Modules** run tools against them.

| Task | How |
| :--- | :--- |
| GUI collection | Run `gkape.exe` -> Target source -> Target destination -> select Targets -> optionally select Modules -> Execute |
| Triage collection from the command line | `kape.exe --tsource C: --tdest C:\cases\kape --target !SANS_Triage` |
| Collect and parse in one run | `kape.exe --tsource C: --tdest C:\cases\kape\tout --target !SANS_Triage --mdest C:\cases\kape\mout --module !EZParser` |
| Browser artifacts only | `--target WebBrowsers` |

## Reading the Output

* Target output mirrors the original paths, so files are easy to locate
* `!EZParser` output is CSV, organized by artifact type; Timeline Explorer is the easiest way to read it
* Check the KAPE console log for files it could not collect, such as locked files

## Related

* [Windows Artifacts](../windows-artifacts.md)
* [Endpoint Malware](../../playbooks/incident-response/endpoint-malware.md) playbook
* [Evidence Handling](../evidence-handling.md)

## Resources

* [KAPE Documentation](https://github.com/EricZimmerman/KapeDocs)
* [KAPE: Fast and Flexible Incident Response (GIAC paper)](https://www.giac.org/paper/gcih/34611/kape-fast-flexible-incident-response/152146)
