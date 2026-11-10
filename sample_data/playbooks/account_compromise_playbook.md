# Account Compromise and Brute Force Playbook (sample)

Owner: Security Operations Center. This is an example document for demonstrating the knowledge base.
It is not real company policy.

## Purpose
This playbook applies when an account shows repeated failed logins followed by a success, a login from an
unusual country, or use of a service account at an unusual time.

## Severity
A successful login after many failures is High. If the account is privileged or a service account, treat it as
Critical and notify the Security Manager within 30 minutes.

## Containment
1. Disable the account or force a password reset, and revoke all active sessions, API keys and tokens.
2. Block the attacking source address at the firewall.
3. Review what the account did after the suspicious login: files accessed, commands run, keys added, forwarding rules created.
4. Isolate the host the account logged in to if there are signs of malicious activity.

## Eradication
1. Remove any unauthorised SSH keys, scheduled tasks, new accounts or forwarding rules.
2. Rotate credentials for every account that shares the same password or that the attacker could have reached.
3. Confirm the account has multi-factor authentication enabled.

## Recovery
Restore access with a new credential after verification. Monitor the account and its source hosts for 14 days.

## Prevention
Enforce account lockout after repeated failures, require multi-factor authentication, disable direct password
login for administrators over SSH in favour of keys, and alert on logins from new locations.
