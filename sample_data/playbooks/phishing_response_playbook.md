# Phishing Response Playbook (sample)

Owner: Security Operations Center. This is an example document for demonstrating the knowledge base.
It is not real company policy.

## Purpose
This playbook covers suspicious emails, malicious attachments, fake login pages and credential theft
that starts with a message to an employee.

## Triage
Ask the user whether they opened the attachment, clicked the link or entered a password. If any of these
happened, treat the case as a confirmed compromise and use the account compromise playbook as well.

## Containment
1. Search all mailboxes for the same sender, subject and attachment hash, and delete or quarantine every copy.
2. Block the sender address and domain, and any link domains, at the mail gateway and web filter.
3. If a user opened an attachment, isolate their computer immediately.
4. If a user entered a password, force a password reset and revoke all active sessions and tokens.

## Eradication
1. Analyse the attachment in a sandbox and record file hashes, dropped files and network connections.
2. Remove any malware and persistence found on the endpoint. Rebuild the computer if malware executed.
3. Confirm that multi-factor authentication is enabled for the affected user.

## Recovery and communication
Restore the user's access after the checks pass. Warn staff with a short message about the campaign, and report
serious campaigns to the Security Manager. Add the indicators to the blocklists.

## Prevention
Run regular phishing awareness training, enable advanced email filtering, restrict script execution such as
PowerShell, and require multi-factor authentication for all accounts.
