# Post-Incident Activity

Learning from the incident, documenting it, and feeding improvements back into preparation.

## Why It Matters

An incident is the most realistic test a security program gets. The lessons learned review turns it into specific fixes; the report gives leadership, auditors, insurers, and sometimes regulators the record they need.

## Reference

### Lessons Learned Review

| Question | Purpose |
| :--- | :--- |
| What happened, and when? | Agree on the timeline |
| How did the attacker get in? | Root cause |
| How was it detected, and how long did that take? | Detection gaps |
| What worked well in the response? | Keep doing it |
| What slowed the response down? | Missing logs, tools, access, contacts, or decisions |
| What will we change, who owns it, and by when? | Turn findings into tracked actions |

### Incident Report

| Section | Contents |
| :--- | :--- |
| Executive summary | What happened, impact, and current status, in plain language |
| Timeline | Key events from initial access through recovery |
| Investigation details | Scope, affected systems and data, attacker activity, evidence |
| Actions taken | Containment, eradication, and recovery steps |
| Root cause and recommendations | How it happened and what will prevent it |
| Appendix | Indicators of compromise, evidence references, screenshots with captions |

Write the report for its audience. Executives need impact and decisions; technical teams need detail; legal may need the report prepared under privilege.

### Follow-up

* Update the incident response plan and playbooks
* Add detections for the techniques that were used
* Fix the root cause and track the remaining actions to completion
* Retain evidence according to legal and policy requirements

## How I Use It

I hold the lessons learned review within a week or two, while details are fresh, and keep it blameless so people are honest about what went wrong. Every finding leaves the meeting with an owner and a date. The most useful output is usually small and specific: a log source that needs longer retention, a phone number missing from the contact list, a detection that would have caught it a week earlier.

## Related

* [Preparation](preparation.md), where the improvements go
* [Incident Response Playbooks](../playbooks/incident-response/index.md)
* [Containment, Eradication, and Recovery](containment-eradication-recovery.md), the previous phase

## Resources

* [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
