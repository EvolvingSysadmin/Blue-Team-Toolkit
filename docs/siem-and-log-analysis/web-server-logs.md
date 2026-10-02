# Web Server Logs

Signs of attacks in web server access and error logs.

## Why It Matters

Web servers face the internet and are constantly scanned and attacked. Access logs record every request, so they show scanning, exploitation attempts, and the use of web shells, often before anything else notices.

## Reference

### Log Locations

| Server | Location |
| :--- | :--- |
| Apache | `/var/log/apache2/access.log` (Debian/Ubuntu) or `/var/log/httpd/access_log` (RHEL) |
| Nginx | `/var/log/nginx/access.log` |
| IIS | `%SystemDrive%\inetpub\logs\LogFiles` |

Each request usually records the client IP, timestamp, HTTP method, requested path and query string, status code, response size, referrer, and user agent.

### What to Look For

| Pattern | What It Can Mean |
| :--- | :--- |
| Many 404s from one source | Directory or vulnerability scanning |
| SQL, HTML, or script tags in the URL or query string | Injection or cross-site scripting attempts |
| Requests for extensions or paths you have not deployed | Scanning, or probing for known vulnerable software |
| Repeated requests to pages that accept input | Brute force or injection attempts |
| Requests to an unfamiliar file that return 200 | A web shell or other unauthorized content |
| Unusual or scripted user agents | Scanners and attack tools often identify themselves |
| Web service stopped, started, or failed messages | Crashes from exploitation attempts, or tampering |

### HTTP Status Codes

| Code | Meaning | Relevance |
| :--- | :--- | :--- |
| 200 | Success | Success for a file you did not deploy is a red flag |
| 400 | Bad request | Malformed requests, often from tools |
| 401 | Authentication required or failed | Brute force when repeated |
| 403 | Forbidden | Access denied; probing restricted areas |
| 404 | Not found | Scanning when frequent from one source |
| 500 | Internal server error | Can indicate injection attempts breaking the application |

## How I Use It

I look at log entries from all servers in a load balancer pool, because the attack may only have hit one. Then I find the noisiest sources and the requests that look nothing like normal traffic:

```bash
# Requests per client IP, most active first
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head

# 404s by client IP
awk '$9 == 404 {print $1}' access.log | sort | uniq -c | sort -rn | head

# Common injection and traversal patterns
grep -iE "union.*select|<script|\.\./|/etc/passwd|cmd=|exec\(" access.log
```

The field positions assume the default combined log format.

## Related

* [Log Review Approach](log-review-approach.md)
* [Exploited Edge Device](../playbooks/incident-response/edge-device-exploitation.md) playbook

## Resources

* [Critical Log Review Checklist for Security Incidents](https://zeltser.com/security-incident-log-review-checklist/)
