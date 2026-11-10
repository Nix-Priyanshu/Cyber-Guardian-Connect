"""
Dashboard calculations.

Everything here works on the list of incidents (as dictionaries in the common
incident format) and returns plain Python data, so it is easy to test and has
no dependency on Streamlit. No API calls are made: the dashboard is built only
from the data the connectors delivered.
"""
from collections import Counter
from typing import Dict, List, Tuple

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Unknown"]
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
CLOSED_STATUSES = {"contained", "resolved", "closed"}


def is_active(incident: dict) -> bool:
    """An incident is active until its status says it is contained, resolved or closed."""
    return str(incident.get("status", "")).strip().lower() not in CLOSED_STATUSES


def is_private_ip(ip: str) -> bool:
    """True for private (RFC 1918) and loopback addresses."""
    try:
        o = [int(part) for part in ip.split(".")]
    except ValueError:
        return False
    if len(o) != 4:
        return False
    return (
        o[0] == 10
        or (o[0] == 172 and 16 <= o[1] <= 31)
        or (o[0] == 192 and o[1] == 168)
        or o[0] == 127
    )


def sort_incidents(incidents: List[dict]) -> List[dict]:
    """Newest first (by creation time text, which sorts correctly for ISO dates)."""
    return sorted(incidents, key=lambda i: (str(i.get("created_at", "")), str(i.get("id", ""))), reverse=True)


def overall_threat_level(incidents: List[dict]) -> str:
    """
    NO_DATA    nothing connected yet
    CONTAINED  incidents exist but none is still active
    otherwise  the highest severity among ACTIVE incidents (CRITICAL, HIGH, ...)
    An active incident with unknown severity gives UNKNOWN, never a reassuring level.
    """
    if not incidents:
        return "NO_DATA"
    active = [i for i in incidents if is_active(i)]
    if not active:
        return "CONTAINED"
    worst = max(active, key=lambda i: SEVERITY_RANK.get(i.get("severity", "Unknown"), 0))
    return str(worst.get("severity", "Unknown")).upper()


def severity_counts(incidents: List[dict], active_only: bool = False) -> Dict[str, int]:
    counts = Counter(i.get("severity", "Unknown") for i in incidents if not active_only or is_active(i))
    return {level: counts.get(level, 0) for level in SEVERITY_ORDER}


def top_indicators(incidents: List[dict], kind: str, limit: int = 10) -> List[Tuple[str, int]]:
    """
    Most frequent indicators of one kind ('ips', 'domains', 'hashes', 'emails',
    'cves', 'urls'), counted by the number of incidents that mention them.
    """
    counter = Counter()
    for incident in incidents:
        for value in set((incident.get("indicators") or {}).get(kind, [])):
            counter[value] += 1
    return counter.most_common(limit)


def unique_indicator_count(incidents: List[dict], kind: str) -> int:
    return len(top_indicators(incidents, kind, limit=10 ** 6))


def external_ip_count(incidents: List[dict]) -> int:
    return sum(1 for ip, _ in top_indicators(incidents, "ips", limit=10 ** 6) if not is_private_ip(ip))


def technique_counts(incidents: List[dict]) -> List[Tuple[str, str, int]]:
    """(technique id, name, number of incidents), most common first."""
    counter, names = Counter(), {}
    for incident in incidents:
        for technique in {t["id"]: t for t in incident.get("techniques") or []}.values():
            counter[technique["id"]] += 1
            names[technique["id"]] = technique.get("name", "")
    return [(tid, names[tid], count) for tid, count in counter.most_common()]


def host_summary(incidents: List[dict]) -> List[dict]:
    """One row per affected host with its incident count and worst severity."""
    hosts: Dict[str, dict] = {}
    for incident in incidents:
        host = incident.get("host") or {}
        name = host.get("hostname", "")
        if not name:
            continue
        row = hosts.setdefault(name, {
            "Host": name, "Department": host.get("department", ""), "User": host.get("username", ""),
            "IP": host.get("ip", ""), "Incidents": 0, "Worst severity": "Unknown",
        })
        row["Incidents"] += 1
        severity = incident.get("severity", "Unknown")
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(row["Worst severity"], 0):
            row["Worst severity"] = severity
    return sorted(hosts.values(), key=lambda r: (-SEVERITY_RANK.get(r["Worst severity"], 0), -r["Incidents"]))
