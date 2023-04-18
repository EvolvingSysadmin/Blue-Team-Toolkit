# Web Server Log Analysis

* Description: list of items to consider for web server forensic analysis
* What to scrutinize
  * Excessive access attempts to non-existent files
  * Code (SQL, HTML) seen as part of the URL
  * Access to extensions you have not implemented
  * Web service stopped/started/failed messages
  * Access to “risky” pages that accept user input
  * Look at logs on all servers in the load balancer pool
  * HTTP Error Codes
    * Error code 200 on files that are not yours
    * Failed user authentication: Error code 401, 403
    * Invalid request: Error code 400
    * Internal server error: Error code 500
* Resources
  * [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
