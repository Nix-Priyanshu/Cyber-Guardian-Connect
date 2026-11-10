# Ransomware Response Playbook (sample)

Owner: Security Operations Center. This is an example document for demonstrating the knowledge base.
It is not real company policy.

## Purpose
This playbook describes how the SOC responds when files are being encrypted, a ransom note appears,
or endpoint protection reports ransomware behaviour.

## Severity and escalation
Treat every confirmed ransomware case as Critical. Notify the Security Manager within 30 minutes and
the Head of IT within 1 hour. Open a major incident record and assign an incident commander.

## Immediate containment (first 15 minutes)
1. Isolate the affected host from the network at the EDR console or by disconnecting the cable. Do not power it off, because memory evidence would be lost.
2. Disable the user account and any administrator account that was used on the host.
3. Block the command and control addresses and domains at the firewall and DNS filter.
4. Disconnect shared drives and file servers that the host could reach, and suspend backup jobs so clean backups are not overwritten.
5. Check neighbouring hosts for the same file extension, ransom note or process name.

## Eradication
1. Identify the initial access: phishing email, exposed remote access service, or stolen credentials.
2. Remove the malicious files, scheduled tasks and registry run keys that provide persistence.
3. Reset passwords for all accounts that logged in to the affected hosts, and rotate privileged and service account credentials.
4. Patch the vulnerability that was used, if one was involved.

## Recovery
1. Rebuild the affected hosts from a trusted image. Do not clean and reuse an infected system.
2. Restore data from the last known clean backup and verify file integrity before reconnecting the host.
3. Return systems to normal operation in stages, and monitor closely for 30 days.
4. Do not pay a ransom without executive and legal approval.

## After the incident
Hold a lessons learned review within 5 working days. Update detection rules, and record the indicators of
compromise found.
