"""
Data and logic for the simulated security web application.

This plays the role of "the company's SOC platform" that CyberGuardian
connects to. It deliberately uses its OWN field names (risk, asset, dst,
attack_techniques ...) that differ from CyberGuardian's common incident
format, so the connector has real conversion work to do.

It is plain Python with no web framework, so it can be tested on its own.
`main.py` wraps it in a FastAPI app.
"""
import hashlib
import random
from copy import deepcopy
from datetime import datetime, timedelta, timezone

ALLOWED_ACTIONS = {"block_ip", "isolate_host", "disable_account"}


def _fake_hash(label: str) -> str:
    """A well-formed SHA-256 for a made-up sample file (not real malware)."""
    return hashlib.sha256(label.encode()).hexdigest()


SAMPLE_INCIDENTS = [
    {
        "id": "INC-2026-0001",
        "title": "Phishing-led compromise with PowerShell execution and data exfiltration",
        "created": "2026-08-07T09:18:00Z",
        "risk": "critical",
        "state": "contained",
        "description": (
            "Multiple failed logins were followed by a successful authentication from an "
            "unusual external IP address. PowerShell then executed an encoded command, "
            "downloaded a payload, contacted a Command and Control server and exfiltrated "
            "sensitive financial documents. The incident is believed to have started from a "
            "phishing email with a disguised executable attachment."
        ),
        "asset": {"name": "FINANCE-PC-07", "os": "Windows 11 Enterprise", "dept": "Finance",
                  "owner": "john.smith", "ip": "192.168.10.25"},
        "network": {"src": "192.168.10.25", "dst": ["185.244.25.17", "45.91.203.56"],
                    "proto": "HTTPS", "dport": 443, "geo": "Russia", "bytes_out": "1.8 GB"},
        "indicators": [
            {"type": "ip", "value": "185.244.25.17"},
            {"type": "ip", "value": "45.91.203.56"},
            {"type": "domain", "value": "secure-update-check.com"},
            {"type": "domain", "value": "cdn-security-sync.net"},
            {"type": "email", "value": "support@company-security-alert.com"},
            {"type": "hash", "value": "a71d4a1f92c2d15a9e0fa70f95c1bc74b618ec741de2aa4b4a0b7cf54a8d8819"},
            {"type": "cve", "value": "CVE-2023-23397"},
            {"type": "cve", "value": "CVE-2021-34527"},
        ],
        "attack_techniques": ["T1566", "T1059.001", "T1003", "T1041", "T1547", "T1071.001"],
        "events": [
            {"ts": "08:40", "msg": "Phishing email delivered"},
            {"ts": "08:41", "msg": "User opened attachment"},
            {"ts": "08:43", "msg": "PowerShell executed encoded command"},
            {"ts": "08:44", "msg": "Persistence registry key created"},
            {"ts": "08:46", "msg": "Credential dumping initiated"},
            {"ts": "08:48", "msg": "Communication established with Command and Control server"},
            {"ts": "09:01", "msg": "Data exfiltration started"},
            {"ts": "09:12", "msg": "Outbound transfer completed"},
            {"ts": "09:18", "msg": "SOC generated Critical alert"},
            {"ts": "09:20", "msg": "Endpoint isolated"},
        ],
        "actor": "APT29",
    },
    {
        "id": "INC-2026-0002",
        "title": "SSH brute force followed by a successful login on a web server",
        "created": "2026-08-12T02:14:00Z",
        "risk": "high",
        "state": "investigating",
        "description": (
            "Hundreds of failed SSH logins from one external address were followed by a "
            "successful login to a service account. A new SSH key was added shortly after."
        ),
        "asset": {"name": "LINUX-WEB-02", "os": "Ubuntu 22.04", "dept": "IT Infrastructure",
                  "owner": "svc-backup", "ip": "10.0.4.12"},
        "network": {"src": "203.0.113.45", "dst": ["10.0.4.12"], "proto": "SSH", "dport": 22,
                    "geo": "Unknown", "bytes_out": "12 MB"},
        "indicators": [{"type": "ip", "value": "203.0.113.45"}],
        "attack_techniques": ["T1110", "T1078", "T1021"],
        "events": [
            {"ts": "02:03:10", "msg": "Repeated failed SSH logins from 203.0.113.45"},
            {"ts": "02:09:41", "msg": "Successful login as svc-backup"},
            {"ts": "02:11:05", "msg": "New SSH authorized key added"},
            {"ts": "02:14:00", "msg": "SIEM correlation alert raised"},
        ],
        "actor": "",
    },
    {
        "id": "INC-2026-0003",
        "title": "Ransomware activity detected on the main file server",
        "created": "2026-08-15T14:32:00Z",
        "risk": "critical",
        "state": "open",
        "description": (
            "A file server began renaming and encrypting shared documents after an "
            "obfuscated script ran under an administrator account. A ransom note was "
            "dropped in several folders."
        ),
        "asset": {"name": "FILESRV-01", "os": "Windows Server 2019", "dept": "Operations",
                  "owner": "admin.ops", "ip": "10.0.2.5"},
        "network": {"src": "10.0.2.5", "dst": ["198.51.100.23"], "proto": "HTTPS", "dport": 443,
                    "geo": "Unknown", "bytes_out": "240 MB"},
        "indicators": [
            {"type": "ip", "value": "198.51.100.23"},
            {"type": "domain", "value": "files-restore-portal.top"},
            {"type": "hash", "value": _fake_hash("cyberguardian-sample-ransomware")},
        ],
        "attack_techniques": ["T1078", "T1027", "T1059.001", "T1486"],
        "events": [
            {"ts": "14:20:03", "msg": "Administrator login from an unusual workstation"},
            {"ts": "14:24:47", "msg": "Obfuscated PowerShell script executed"},
            {"ts": "14:29:10", "msg": "Mass file rename activity started"},
            {"ts": "14:32:00", "msg": "EDR raised a ransomware behaviour alert"},
        ],
        "actor": "",
    },
    {
        "id": "INC-2026-0004",
        "title": "Unusually large download by a contractor account",
        "created": "2026-08-18T18:05:00Z",
        "risk": "medium",
        "state": "open",
        "description": (
            "A contractor account downloaded far more data than usual from the document "
            "store outside working hours."
        ),
        "asset": {"name": "CONTRACTOR-LT-11", "os": "Windows 11 Pro", "dept": "Contractors",
                  "owner": "a.kumar.ext", "ip": "10.0.9.41"},
        "network": {"src": "10.0.9.41", "dst": ["10.0.1.20"], "proto": "SMB", "dport": 445,
                    "geo": "Internal", "bytes_out": "3.2 GB"},
        "indicators": [{"type": "ip", "value": "10.0.9.41"}],
        "attack_techniques": ["T1078", "T1041"],
        "events": [
            {"ts": "17:40:22", "msg": "Contractor logged in after hours"},
            {"ts": "17:52:09", "msg": "Bulk file access on the document store"},
            {"ts": "18:05:00", "msg": "Data loss prevention rule triggered"},
        ],
        "actor": "",
    },
]

# Templates used by simulate_new() to create a fresh incident during a live demo.
_TEMPLATES = [
    {
        "title": "Brute force login attempts against a remote service",
        "risk": "high",
        "description": "Many failed logins from one external address were seen against {host}.",
        "techniques": ["T1110", "T1078"],
        "proto": "SSH", "dport": 22,
        "events": ["Repeated failed logins from {ip}", "Account lockout threshold reached on {host}"],
    },
    {
        "title": "Suspicious beaconing to an unknown domain",
        "risk": "high",
        "description": "{host} is making regular outbound connections to {ip}, a pattern typical of malware beaconing.",
        "techniques": ["T1071", "T1105"],
        "proto": "HTTPS", "dport": 443,
        "events": ["Regular outbound connections to {ip}", "DNS request for a newly registered domain",
                   "EDR flagged an unsigned process on {host}"],
    },
    {
        "title": "Port scan from an external address",
        "risk": "low",
        "description": "An external address scanned several services exposed by {host}.",
        "techniques": ["T1046"],
        "proto": "TCP", "dport": 0,
        "events": ["Sequential connection attempts from {ip}", "Firewall blocked the scan"],
    },
]

_SIM_HOSTS = [
    ("HR-PC-03", "Windows 11 Pro", "Human Resources"),
    ("DEV-LAPTOP-14", "Ubuntu 22.04", "Engineering"),
    ("SALES-PC-09", "Windows 11 Enterprise", "Sales"),
    ("WEB-PROXY-01", "Debian 12", "IT Infrastructure"),
]


class IncidentStore:
    """In-memory store for incidents and the actions requested on them."""

    def __init__(self):
        self._incidents = deepcopy(SAMPLE_INCIDENTS)
        self._actions = []

    # ---- reading ----
    def list_summaries(self):
        return [
            {"id": i["id"], "title": i["title"], "risk": i["risk"],
             "state": i["state"], "created": i["created"]}
            for i in self._incidents
        ]

    def get(self, incident_id):
        for incident in self._incidents:
            if incident["id"] == incident_id:
                return deepcopy(incident)
        return None

    def list_actions(self):
        return deepcopy(self._actions)

    # ---- writing ----
    def _next_id(self):
        numbers = [int(i["id"].split("-")[-1]) for i in self._incidents]
        return f"INC-2026-{max(numbers, default=0) + 1:04d}"

    def simulate_new(self, rng=None):
        """Create a new open incident, as if the platform just detected it."""
        rng = rng or random
        template = rng.choice(_TEMPLATES)
        host_name, host_os, dept = rng.choice(_SIM_HOSTS)
        external_ip = f"203.0.113.{rng.randint(2, 250)}"
        internal_ip = f"10.0.{rng.randint(1, 20)}.{rng.randint(2, 250)}"
        now = datetime.now(timezone.utc)

        messages = [m.format(host=host_name, ip=external_ip) for m in template["events"]]
        events = [
            {"ts": (now - timedelta(minutes=len(messages) - n)).strftime("%H:%M:%S"), "msg": msg}
            for n, msg in enumerate(messages)
        ]
        incident = {
            "id": self._next_id(),
            "title": template["title"],
            "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "risk": template["risk"],
            "state": "open",
            "description": template["description"].format(host=host_name, ip=external_ip),
            "asset": {"name": host_name, "os": host_os, "dept": dept, "owner": "", "ip": internal_ip},
            "network": {"src": external_ip, "dst": [internal_ip], "proto": template["proto"],
                        "dport": template["dport"], "geo": "Unknown", "bytes_out": ""},
            "indicators": [{"type": "ip", "value": external_ip}],
            "attack_techniques": list(template["techniques"]),
            "events": events,
            "actor": "",
        }
        self._incidents.append(incident)
        return deepcopy(incident)

    def record_action(self, incident_id, action, target, requested_by="cyberguardian"):
        """
        Record a response action requested by a connected app.
        Raises KeyError for an unknown incident and ValueError for a bad request.
        """
        if action not in ALLOWED_ACTIONS:
            raise ValueError(f"Unsupported action '{action}'. Allowed: {sorted(ALLOWED_ACTIONS)}")
        if not str(target).strip():
            raise ValueError("An action needs a target (an IP address, host name or account).")
        incident = next((i for i in self._incidents if i["id"] == incident_id), None)
        if incident is None:
            raise KeyError(incident_id)

        record = {
            "id": len(self._actions) + 1,
            "incident_id": incident_id,
            "action": action,
            "target": str(target).strip(),
            "requested_by": requested_by,
            "status": "executed",
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        self._actions.append(record)
        if incident["state"] in ("open", "investigating"):
            incident["state"] = "contained"
        return deepcopy(record)
