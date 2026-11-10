"""
The common incident format.

Every connector, whatever the source looks like, converts its data into
`Incident`. The dashboard, the AI analysis and the report code only ever see
this one structure, so adding a new source never means touching them.
"""
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Dict, List

# Readable names for common MITRE ATT&CK technique IDs.
MITRE_NAMES = {
    "T1566": "Phishing", "T1566.001": "Spearphishing Attachment",
    "T1059": "Command and Scripting Interpreter", "T1059.001": "PowerShell",
    "T1003": "OS Credential Dumping", "T1041": "Exfiltration Over C2 Channel",
    "T1547": "Boot or Logon Autostart Execution", "T1547.001": "Registry Run Keys",
    "T1071": "Application Layer Protocol", "T1071.001": "Web Protocols",
    "T1105": "Ingress Tool Transfer", "T1053": "Scheduled Task/Job",
    "T1027": "Obfuscated Files or Information", "T1486": "Data Encrypted for Impact",
    "T1078": "Valid Accounts", "T1190": "Exploit Public-Facing Application",
    "T1110": "Brute Force", "T1021": "Remote Services",
    "T1082": "System Information Discovery", "T1204": "User Execution",
    "T1055": "Process Injection", "T1046": "Network Service Discovery",
}


def technique_name(technique_id: str) -> str:
    return MITRE_NAMES.get(technique_id, "Technique")


def normalize_severity(value: Any) -> str:
    """Map any severity wording to Low / Medium / High / Critical, else Unknown."""
    text = str(value or "").lower()
    for level in ("critical", "high", "medium", "low"):
        if level in text:
            return level.capitalize()
    if "moderate" in text:
        return "Medium"
    return "Unknown"


def _build(cls, data: Dict[str, Any]):
    """Create a dataclass from a dict, ignoring keys the class does not know."""
    known = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in (data or {}).items() if k in known})


@dataclass
class Host:
    hostname: str = ""
    os: str = ""
    department: str = ""
    username: str = ""
    ip: str = ""


@dataclass
class Network:
    source_ip: str = ""
    destination_ips: List[str] = field(default_factory=list)
    protocol: str = ""
    port: str = ""
    country: str = ""
    bytes_out: str = ""


@dataclass
class Indicators:
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)

    def total(self) -> int:
        return sum(len(getattr(self, f.name)) for f in fields(self))


@dataclass
class Technique:
    id: str
    name: str = ""


@dataclass
class TimelineEvent:
    time: str
    event: str


@dataclass
class Incident:
    id: str
    source: str = ""            # name of the connection this came from
    title: str = ""
    severity: str = "Unknown"   # Low / Medium / High / Critical / Unknown
    status: str = ""
    created_at: str = ""
    summary: str = ""
    threat_actor: str = ""
    host: Host = field(default_factory=Host)
    network: Network = field(default_factory=Network)
    indicators: Indicators = field(default_factory=Indicators)
    techniques: List[Technique] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    raw: Any = None             # original payload, kept for the AI features

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Incident":
        data = dict(data or {})
        return cls(
            id=data.get("id", ""),
            source=data.get("source", ""),
            title=data.get("title", ""),
            severity=data.get("severity", "Unknown"),
            status=data.get("status", ""),
            created_at=data.get("created_at", ""),
            summary=data.get("summary", ""),
            threat_actor=data.get("threat_actor", ""),
            host=_build(Host, data.get("host")),
            network=_build(Network, data.get("network")),
            indicators=_build(Indicators, data.get("indicators")),
            techniques=[_build(Technique, t) for t in data.get("techniques") or []],
            timeline=[_build(TimelineEvent, e) for e in data.get("timeline") or []],
            raw=data.get("raw"),
        )
