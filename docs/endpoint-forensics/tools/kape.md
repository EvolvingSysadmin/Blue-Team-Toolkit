# KAPE

* Description: Kroll Artifact Parser and Extractor; collects forensic artifacts from a live system or mounted image (Targets) and parses them with tools such as the Eric Zimmerman suite (Modules), usually in minutes
* Installation: download from <https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape>
* Usage
  * GUI: run gkape.exe -> select Target source -> select Target destination -> select Targets (for example `!SANS_Triage` or `Chrome`) -> optionally select Modules -> Execute
  * Command line example: `kape.exe --tsource C: --tdest C:\cases\kape --target !SANS_Triage`
* Resources
  * [How to use Kape for Fast and Flexible Incident Response](https://www.giac.org/paper/gcih/34611/kape-fast-flexible-incident-response/152146)
  * [KAPE Docs](https://github.com/EricZimmerman/KapeDocs)
