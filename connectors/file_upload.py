"""
Connector for an uploaded text report.

This reuses the parsing ideas from the original CyberGuardian AI project
(regex indicator extraction, "Label:\\nValue" fields, timeline lines) and
converts the result into the common incident format.
"""
import re
from datetime import datetime
from typing import List, Tuple

from .base import BaseConnector, ConnectorError
from .models import (
    Host, Incident, Indicators, Network, Technique, TimelineEvent,
    normalize_severity, technique_name,
)

_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Domains are matched only for common TLDs, to avoid picking up file names like "update.exe".
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|online|site|cc|tk)\b",
    re.IGNORECASE,
)
_TIME_DASH_RE = re.compile(r"^(\d{1,2}:\d{2}(?::\d{2})?)\s*[-–—]\s*(.+)$")
_TIME_ONLY_RE = re.compile(r"^\d{1,2}:\d{2}(?::\d{2})?$")
_INLINE_FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 /&()\-]{1,40}):[ \t]+(\S.*)$")


def _unique(items) -> List[str]:
    """Remove duplicates but keep the order things first appeared."""
    return list(dict.fromkeys(items))


def parse_key_values(text: str) -> dict:
    """
    Read both common report styles into one dict:
        "Incident ID: INC-1"        (label and value on one line)
        "Hostname:\\nFINANCE-PC-07"  (value on the following line)
    The first occurrence of a label wins.
    """
    lines = [line.strip() for line in text.splitlines()]
    fields = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        inline = _INLINE_FIELD_RE.match(line)
        if inline and len(inline.group(2)) <= 160:
            fields.setdefault(inline.group(1).strip(), inline.group(2).strip())
            i += 1
            continue
        if line.endswith(":") and 2 <= len(line) <= 60 and not line.startswith("="):
            j = i + 1
            while j < len(lines) and lines[j] == "":
                j += 1
            if j < len(lines):
                value = lines[j]
                if value and not value.startswith("=") and not value.endswith(":") and len(value) <= 160:
                    fields.setdefault(line[:-1].strip(), value)
                    i = j + 1
                    continue
        i += 1
    return fields


def get_field(fields: dict, *names: str) -> str:
    """Find a field by name, ignoring case. Exact matches win over partial ones."""
    lowered = {key.lower(): value for key, value in fields.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    for name in names:
        for key, value in lowered.items():
            if name.lower() in key:
                return value
    return ""


def extract_section(text: str, title: str) -> str:
    """Return the body of a section that sits between '====' lines under `title`."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().upper() == title.upper():
            body = []
            for following in lines[index + 1:]:
                if following.strip().startswith("="):
                    if body:
                        break
                    continue            # the rule line right under the title
                body.append(following.strip())
            return " ".join(part for part in body if part)
    return ""


def _to_seconds(clock: str) -> int:
    parts = [int(p) for p in clock.split(":")]
    while len(parts) < 3:
        parts.append(0)
    return parts[0] * 3600 + parts[1] * 60 + parts[2]


def extract_timeline(text: str) -> List[Tuple[str, str]]:
    """Find '08:51:12 - event' and 'time line, then event line' entries, sorted by time."""
    lines = [line.strip() for line in text.splitlines()]
    events = []
    i = 0
    while i < len(lines):
        line = lines[i]
        dash = _TIME_DASH_RE.match(line)
        if dash:
            events.append((dash.group(1), dash.group(2).strip()))
            i += 1
            continue
        if _TIME_ONLY_RE.match(line):
            j = i + 1
            while j < len(lines) and lines[j] == "":
                j += 1
            if (
                j < len(lines) and lines[j]
                and not lines[j].startswith("=")
                and not _TIME_ONLY_RE.match(lines[j])
                and not _TIME_DASH_RE.match(lines[j])
                and len(lines[j]) <= 160
            ):
                events.append((line, lines[j]))
                i = j + 1
                continue
        i += 1
    events.sort(key=lambda pair: _to_seconds(pair[0]))
    return events[:60]


def extract_indicators(text: str, exclude_emails=()) -> Indicators:
    """Pull IPs, domains, hashes, emails, CVEs and URLs out of free text."""
    skip = {e.lower() for e in exclude_emails if e}   # e.g. the phishing victim's own address
    all_emails = _unique(_EMAIL_RE.findall(text))
    emails = [e for e in all_emails if e.lower() not in skip]
    # Domains that only appear as part of an email address are not reported as separate domains.
    email_domains = {e.split("@", 1)[1].lower() for e in all_emails}
    urls = _unique(_URL_RE.findall(text))
    domains = [d.lower() for d in _DOMAIN_RE.findall(text)]
    domains = [d for d in _unique(domains) if d not in email_domains]
    return Indicators(
        ips=_unique(_IP_RE.findall(text)),
        domains=domains,
        hashes=_unique(h.lower() for h in _HASH_RE.findall(text)),
        emails=emails,
        cves=_unique(m.upper() for m in _CVE_RE.findall(text)),
        urls=urls,
    )


def _parse_date(value: str) -> str:
    """Turn '07 August 2026' into '2026-08-07'; keep the original if it is not a known format."""
    for pattern in ("%d %B %Y", "%Y-%m-%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(value.strip(), pattern).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return value.strip()


def _short_title(summary: str, fallback: str) -> str:
    if not summary:
        return fallback
    first_sentence = re.split(r"(?<=[.!?])\s", summary, maxsplit=1)[0]
    return first_sentence if len(first_sentence) <= 110 else first_sentence[:107].rstrip() + "..."


def parse_report(text: str, source: str, filename: str) -> Incident:
    """Convert the text of one incident report into the common incident format."""
    fields = parse_key_values(text)
    summary = extract_section(text, "EXECUTIVE SUMMARY")
    # Some reports end the summary with a "Overall Severity: X" line; that is a field, not prose.
    summary = re.sub(r"\s*Overall Severity:\s*\w+\s*$", "", summary, flags=re.IGNORECASE)
    severity_text = get_field(fields, "overall severity", "severity")
    if not severity_text:
        match = re.search(r"severity\s*[:\-]\s*(\w+)", text, re.IGNORECASE)
        severity_text = match.group(1) if match else ""

    techniques = _unique(_MITRE_RE.findall(text))
    destinations = [
        v for v in (get_field(fields, "destination ip"), get_field(fields, "secondary destination ip")) if v
    ]

    return Incident(
        id=get_field(fields, "incident id") or f"FILE-{filename}",
        source=source,
        title=_short_title(summary, f"Uploaded report: {filename}"),
        severity=normalize_severity(severity_text),
        status="Imported from file",
        created_at=_parse_date(get_field(fields, "report date")),
        summary=summary,
        threat_actor=get_field(fields, "threat actor"),
        host=Host(
            hostname=get_field(fields, "hostname"),
            os=get_field(fields, "operating system"),
            department=get_field(fields, "department"),
            username=get_field(fields, "username", "user name"),
            ip=get_field(fields, "internal ip address"),
        ),
        network=Network(
            source_ip=get_field(fields, "source ip"),
            destination_ips=destinations,
            protocol=get_field(fields, "protocol"),
            port=get_field(fields, "destination port"),
            country=get_field(fields, "country"),
            bytes_out=get_field(fields, "bytes uploaded", "bytes exfiltrated"),
        ),
        indicators=extract_indicators(text, exclude_emails=[get_field(fields, "recipient")]),
        techniques=[Technique(id=t, name=technique_name(t)) for t in techniques],
        timeline=[TimelineEvent(time=t, event=e) for t, e in extract_timeline(text)],
        raw=text,
    )


class FileUploadConnector(BaseConnector):
    type_label = "File upload"

    def __init__(self, name: str, filename: str, text: str):
        super().__init__(name)
        self.filename = filename
        self.text = text or ""

    def test_connection(self) -> Tuple[bool, str]:
        if not self.text.strip():
            return False, "The file is empty."
        return True, f"Report loaded ({len(self.text):,} characters)."

    def fetch_incidents(self) -> List[Incident]:
        if not self.text.strip():
            raise ConnectorError("The file is empty.")
        return [parse_report(self.text, self.name, self.filename)]
