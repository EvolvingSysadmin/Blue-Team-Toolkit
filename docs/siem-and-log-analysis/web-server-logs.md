# Web Server Logs

* Description: items to consider for web server log analysis
* Log locations
  * Apache: `/var/log/apache2/access.log` (Debian/Ubuntu) or `/var/log/httpd/access_log` (RHEL)
  * Nginx: `/var/log/nginx/access.log`
  * IIS: `%SystemDrive%\inetpub\logs\LogFiles`
* What to scrutinize
  * Excessive requests for non-existent files (many 404s from one source usually means scanning)
  * Code (SQL, HTML, script tags) in the URL or query string
  * Requests for file extensions or paths you have not deployed
  * Web service stopped, started, or failed messages
  * Access to pages that accept user input
  * Logs from all servers in a load balancer pool
  * Unusual user agents (scanners and scripts often identify themselves)
* HTTP Status Codes
  * 200: success; a 200 response for a file you did not deploy can mean a web shell or other unauthorized content
  * 401: authentication required or failed
  * 403: forbidden (authenticated or not, access is denied)
  * 404: not found
  * 400: bad request
  * 500: internal server error, which can indicate injection attempts against the application
* Resources
  * [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
