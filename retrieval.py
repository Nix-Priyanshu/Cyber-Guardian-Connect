"""
Retrieval for the AI Copilot.

Each incident is split into small labelled chunks (overview, host and network,
indicators, ATT&CK techniques, timeline, pieces of the original report, and the
response actions taken on it). For each question the most relevant chunks are
found with BM25, a standard keyword-ranking method, and only those chunks are
given to the language model.

This is the "retrieval" half of retrieval-augmented generation. It needs no
embedding model and no extra API key, and it handles exact security terms well
(IP addresses, incident IDs, CVEs, file names). The index is small, so it is
rebuilt for every question and always reflects the latest synced data.
"""
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

RAW_CHUNK_CHARS = 900
MAX_RAW_CHUNKS = 30
TIMELINE_CHUNK_EVENTS = 8

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._:\-]*")
_SPLIT_RE = re.compile(r"[._:\-]+")
STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "what", "which", "who", "how", "of", "to", "in", "on",
    "for", "and", "or", "did", "do", "does", "me", "my", "it", "this", "that", "with", "any", "there",
    "about", "tell", "show", "give", "please", "can", "you", "i", "we", "be", "been", "has", "have",
}


@dataclass
class Chunk:
    incident_key: str
    incident_id: str
    label: str
    text: str


_SUFFIXES = ("ations", "ation", "ings", "ing", "ied", "ies", "ed", "es", "s", "y", "e")


def stem(word: str) -> str:
    """A very small stemmer so 'recover' matches 'recovery' and 'isolated' matches 'isolate'."""
    if not word.isalpha() or len(word) < 5:
        return word
    for suffix in _SUFFIXES:
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            return word[:-len(suffix)]
    return word


def tokenize(text: str) -> List[str]:
    """
    Lower-case words, keeping whole technical tokens (185.244.25.17, cve-2023-23397,
    powershell.exe) and also their word parts (powershell, exe) so both kinds of query match.
    """
    tokens = []
    for raw in _TOKEN_RE.findall(text.lower()):
        token = raw.strip("._:-")
        if not token or token in STOPWORDS:
            continue
        tokens.append(stem(token))
        parts = _SPLIT_RE.split(token)
        if len(parts) > 1:
            tokens.extend(stem(p) for p in parts if len(p) >= 3 and re.search(r"[a-z]", p) and p not in STOPWORDS)
    return tokens


def _join(values) -> str:
    return ", ".join(str(v) for v in values) if values else "none"


def _raw_windows(text: str) -> List[str]:
    """Cut an uploaded report into pieces of about RAW_CHUNK_CHARS, breaking at line ends."""
    windows, current = [], ""
    for line in text.splitlines():
        line = line.strip()
        if not line or set(line) <= {"=", "-"}:
            continue
        if current and len(current) + len(line) + 1 > RAW_CHUNK_CHARS:
            windows.append(current)
            current = ""
        current = f"{current}\n{line}".strip()
    if current:
        windows.append(current)
    return windows[:MAX_RAW_CHUNKS]


def build_incident_chunks(incident: dict) -> List[Chunk]:
    key, iid = incident.get("_key", incident["id"]), incident["id"]
    host = incident.get("host") or {}
    net = incident.get("network") or {}
    ind = incident.get("indicators") or {}

    title = incident.get("title", "")

    def chunk(label, text):
        # The title is repeated in every chunk so a topic word ("ransomware") finds all of its incident.
        return Chunk(key, iid, label, f"Incident {iid} {label}. Incident title: {title}. {text}")

    chunks = [
        chunk("overview",
              f"{incident.get('title', '')}. Severity: {incident.get('severity', 'Unknown')}. "
              f"Status: {incident.get('status') or 'not stated'}. Created: {incident.get('created_at') or 'not stated'}. "
              f"Source system: {incident.get('source', '')}. Threat actor: {incident.get('threat_actor') or 'not stated'}. "
              f"{incident.get('summary', '')}"),
        chunk("host and network",
              f"Host: {host.get('hostname') or 'not stated'}, operating system {host.get('os') or 'not stated'}, "
              f"department {host.get('department') or 'not stated'}, user {host.get('username') or 'not stated'}, "
              f"internal IP {host.get('ip') or 'not stated'}. Network: source IP {net.get('source_ip') or 'not stated'}, "
              f"destination IPs {_join(net.get('destination_ips'))}, protocol {net.get('protocol') or 'not stated'}, "
              f"port {net.get('port') or 'not stated'}, country {net.get('country') or 'not stated'}, "
              f"data sent out (exfiltrated or uploaded) {net.get('bytes_out') or 'not stated'}."),
        chunk("indicators of compromise",
              f"IP addresses: {_join(ind.get('ips'))}. Domains: {_join(ind.get('domains'))}. "
              f"File hashes: {_join(ind.get('hashes'))}. Emails: {_join(ind.get('emails'))}. "
              f"CVEs: {_join(ind.get('cves'))}. URLs: {_join(ind.get('urls'))}."),
    ]
    techniques = [f"{t['id']} {t.get('name', '')}".strip() for t in incident.get("techniques") or []]
    if techniques:
        chunks.append(chunk("MITRE ATT&CK techniques", _join(techniques) + "."))

    events = [f"{e['time']} {e['event']}" for e in incident.get("timeline") or []]
    for start in range(0, len(events), TIMELINE_CHUNK_EVENTS):
        part = events[start:start + TIMELINE_CHUNK_EVENTS]
        chunks.append(chunk("timeline", " ".join(f"[{line}]" for line in part)))

    raw = incident.get("raw")
    if isinstance(raw, str):
        for window in _raw_windows(raw):
            chunks.append(chunk("original report", window))
    return chunks


def build_action_chunks(action_rows: List[dict], incidents: List[dict]) -> List[Chunk]:
    """One chunk per incident describing the response actions decided on it (from the audit log)."""
    by_id = {}
    for row in action_rows:
        by_id.setdefault(row["incident_id"], []).append(row)
    keys = {i["id"]: i.get("_key", i["id"]) for i in incidents}
    titles = {i["id"]: i.get("title", "") for i in incidents}
    chunks = []
    for incident_id, rows in by_id.items():
        lines = [f"{r['decision']} {r['action']} on {r['target']} (result {r['result']}, suggested by "
                 f"{'AI' if r['proposed_by'] == 'ai' else 'rules'})" for r in rows]
        chunks.append(Chunk(keys.get(incident_id, incident_id), incident_id, "response actions",
                            f"Incident {incident_id} response actions taken or decided. Incident title: "
                            f"{titles.get(incident_id, '')}. " + "; ".join(lines) + "."))
    return chunks


def build_chunks(incidents: List[dict], action_rows: Optional[List[dict]] = None) -> List[Chunk]:
    chunks = []
    for incident in incidents:
        chunks += build_incident_chunks(incident)
    if action_rows:
        chunks += build_action_chunks(action_rows, incidents)
    return chunks


class BM25Index:
    """Ranks chunks against a question. k1 and b are the usual BM25 constants."""

    def __init__(self, chunks: List[Chunk], k1: float = 1.5, b: float = 0.75):
        self.chunks, self.k1, self.b = chunks, k1, b
        self._tf = [Counter(tokenize(c.text)) for c in chunks]
        self._len = [sum(tf.values()) for tf in self._tf]
        self._avg = (sum(self._len) / len(self._len)) if self._len else 0.0
        document_frequency: Counter = Counter()
        for tf in self._tf:
            document_frequency.update(tf.keys())
        n = len(chunks)
        self._idf: Dict[str, float] = {
            term: math.log(1 + (n - df + 0.5) / (df + 0.5)) for term, df in document_frequency.items()
        }

    def search(self, query: str, k: int = 6, incident_key: Optional[str] = None) -> List[Tuple[Chunk, float]]:
        terms = set(tokenize(query))
        scored = []
        for index, chunk in enumerate(self.chunks):
            if incident_key and chunk.incident_key != incident_key:
                continue
            tf, length = self._tf[index], self._len[index]
            score = 0.0
            for term in terms:
                count = tf.get(term, 0)
                if not count:
                    continue
                norm = count + self.k1 * (1 - self.b + self.b * length / (self._avg or 1))
                score += self._idf.get(term, 0.0) * count * (self.k1 + 1) / norm
            if score > 0:
                scored.append((chunk, score))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:k]
