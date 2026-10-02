# Containment, Eradication, and Recovery

Stopping the attacker from doing more damage, removing their access, and returning systems to normal operation.

## Why It Matters

Containment limits the damage; eradication makes sure the attacker cannot come back the way they got in or through persistence they left behind; recovery brings the business back. Doing them out of order, or only partly, is how incidents repeat a week later.

## Reference

### Containment Options

| Level | Options |
| :--- | :--- |
| Perimeter | Block inbound and outbound traffic to attacker infrastructure; IDS/IPS rules; WAF policies; DNS sinkholing |
| Network | VLAN isolation; segment isolation at the router or firewall; port blocking; IP or MAC blocking; ACLs |
| Endpoint | EDR network isolation; disconnecting from the network; host firewall rules; HIPS actions |
| Identity | Disabling accounts; resetting passwords; revoking sessions and tokens; removing attacker MFA methods |
| Data | Taking file shares offline; protecting backups by disconnecting or locking them down |

!!! warning "Isolate, don't power off"
    Powering off a compromised host destroys memory, which can hold the attacker's tools, injected code, network connections, and sometimes encryption keys. Use EDR isolation or unplug the network cable, and capture memory first when it matters.

### Eradication

| Action | Details | Why |
| :--- | :--- | :--- |
| Remove persistence | Scheduled tasks, services, Run keys, web shells, inbox rules, OAuth apps, attacker-created accounts | Anything left behind is a way back in |
| Rebuild compromised systems | Reimage instead of cleaning wherever possible | A cleaned system is only as clean as your understanding of the attack |
| Reset exposed credentials | Every account the attacker had or could have had, including service accounts | Stolen passwords and tokens outlive the malware |
| Close the access vector | Patch, reconfigure, or remove the exposed service or account | Otherwise the attacker can repeat the same entry |

### Recovery

| Action | Details | Why |
| :--- | :--- | :--- |
| Restore from known-good backups | Backups that predate the compromise | Later backups may contain the attacker's changes |
| Patch and harden before reconnecting | Apply updates and fix the weaknesses that were used | A restored system is otherwise just as vulnerable |
| Update detections | EDR, antivirus, IDS/IPS, and SIEM rules with indicators from the incident | Catches a return attempt early |
| Monitor closely | Watch restored systems and affected accounts for at least a few weeks | Reinfection often comes back through access that was missed |
| Share indicators | With partners, ISACs, and vendors as appropriate | Helps others and often brings back useful intelligence |

## How I Use It

I contain as soon as the scope is good enough, not perfect: an attacker with an active session in a mailbox does not wait for me to finish reading the logs. For a single host or account, that means isolating and resetting right away. For a widespread compromise where the attacker has privileged access, I hold off on piecemeal containment and plan a coordinated eviction instead, so they cannot react to what I am doing.

For recovery, I would rather rebuild than clean. Reimaging a host or rebuilding a server from a known-good state is something I can trust; a cleaned system is only as clean as my understanding of everything the attacker did.

## Related

| Page | Relevance |
| :--- | :--- |
| [Ransomware](../playbooks/incident-response/ransomware.md) | Containment and recovery at the largest scale |
| [Active Directory Privileged Compromise](../playbooks/incident-response/ad-privileged-compromise.md) | Coordinated eviction when the attacker has domain access |
| [Memory Artifacts](../endpoint-forensics/memory-artifacts.md) | Capturing memory before containment changes the system |
| [Detection and Analysis](detection-and-analysis.md) | The previous phase |
| [Post-Incident Activity](post-incident-activity.md) | The next phase |

**Resources:** [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
