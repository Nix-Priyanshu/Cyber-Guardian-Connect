"""
AI analysis of one incident.

The incident arrives in the common format, so this code does not care whether
it came from a REST API or an uploaded file. It builds a prompt from the
incident's facts, asks the model for a structured report, and splits the
answer into the sections shown on screen and written into the PDF.

`analyze()` accepts any object with an `invoke(prompt)` method, which is what
LangChain chat models provide. That also lets the tests use a fake model.
"""
import re
from datetime import datetime
from typing import Dict

SECTION_ORDER = [
    "Incident Summary", "Attack Type", "Severity", "Root Cause",
    "Explanation", "Mitigation", "Best Practices", "Disclaimer",
]

DEFAULT_MODELS = {"Gemini": "gemini-3.5-flash", "Groq": "openai/gpt-oss-120b"}

RAW_EXCERPT_LIMIT = 6000   # characters of an uploaded report passed to the model


class AIError(Exception):
    """An AI problem with a message that is safe to show to the user."""


# ------------------------------------------------------------------ model
def get_llm(provider: str, api_key: str, model_name: str, temperature: float = 0.3):
    """Create a LangChain chat model for Gemini or Groq."""
    if not api_key:
        raise AIError(f"Enter your {provider} API key in the sidebar first.")
    try:
        if provider == "Gemini":
            from langchain_google_genai import ChatGoogleGenerativeAI
            return ChatGoogleGenerativeAI(model=model_name, google_api_key=api_key, temperature=temperature)
        from langchain_groq import ChatGroq
        return ChatGroq(model=model_name, api_key=api_key, temperature=temperature)
    except ImportError as exc:
        raise AIError(
            f"The library for {provider} is not installed ({exc.name}). "
            "Run: python -m pip install -r requirements.txt"
        ) from exc


def friendly_llm_error(exc: Exception) -> str:
    """Turn a provider exception into a short message a user can act on."""
    text = str(exc)
    lowered = text.lower()
    if any(k in lowered for k in ("api key", "api_key", "unauthorized", "401", "permission denied")):
        return "The AI provider rejected the API key. Check the key in the sidebar."
    if any(k in lowered for k in ("429", "rate limit", "quota", "resource_exhausted", "too many requests")):
        return "The AI provider's rate limit or quota was reached. Wait a minute and try again."
    if any(k in lowered for k in ("404", "not found", "model_not_found", "does not exist")):
        return "The AI provider does not know that model name. Check the model name in the sidebar."
    if any(k in lowered for k in ("timeout", "timed out", "connection", "resolve", "network")):
        return "Could not reach the AI provider. Check your internet connection."
    return f"The AI request failed: {text[:200]}"


def call_llm(llm, prompt: str) -> str:
    """Send a prompt and return the answer as plain text."""
    try:
        reply = llm.invoke(prompt)
    except Exception as exc:                      # provider errors vary a lot
        raise AIError(friendly_llm_error(exc)) from exc
    content = getattr(reply, "content", reply)
    if isinstance(content, list):                 # some models return a list of parts
        content = "".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in content)
    text = str(content).strip()
    if not text:
        raise AIError("The AI returned an empty answer. Try again.")
    return text


# ------------------------------------------------------------------ prompt
def _join(values) -> str:
    return ", ".join(str(v) for v in values) if values else "none listed"


def build_incident_facts(incident: dict) -> str:
    """The incident's data as plain text the model can read."""
    host = incident.get("host") or {}
    net = incident.get("network") or {}
    ind = incident.get("indicators") or {}
    techniques = [f"{t['id']} ({t.get('name', '')})" for t in incident.get("techniques") or []]
    timeline = [f"{e['time']}  {e['event']}" for e in incident.get("timeline") or []]

    lines = [
        f"Incident ID: {incident.get('id', '')}",
        f"Source system: {incident.get('source', '')}",
        f"Title: {incident.get('title', '')}",
        f"Severity reported by the source: {incident.get('severity', 'Unknown')}",
        f"Status: {incident.get('status', '') or 'not stated'}",
        f"Created: {incident.get('created_at', '') or 'not stated'}",
        f"Threat actor: {incident.get('threat_actor', '') or 'not stated'}",
        f"Description: {incident.get('summary', '') or 'not stated'}",
        "",
        "Affected host:",
        f"  Hostname: {host.get('hostname', '') or 'not stated'}",
        f"  Operating system: {host.get('os', '') or 'not stated'}",
        f"  Department: {host.get('department', '') or 'not stated'}",
        f"  User: {host.get('username', '') or 'not stated'}",
        f"  Internal IP: {host.get('ip', '') or 'not stated'}",
        "",
        "Network:",
        f"  Source IP: {net.get('source_ip', '') or 'not stated'}",
        f"  Destination IPs: {_join(net.get('destination_ips'))}",
        f"  Protocol: {net.get('protocol', '') or 'not stated'}",
        f"  Port: {net.get('port', '') or 'not stated'}",
        f"  Country: {net.get('country', '') or 'not stated'}",
        f"  Data sent out: {net.get('bytes_out', '') or 'not stated'}",
        "",
        "Indicators of compromise:",
        f"  IP addresses: {_join(ind.get('ips'))}",
        f"  Domains: {_join(ind.get('domains'))}",
        f"  File hashes: {_join(ind.get('hashes'))}",
        f"  Emails: {_join(ind.get('emails'))}",
        f"  CVEs: {_join(ind.get('cves'))}",
        f"  URLs: {_join(ind.get('urls'))}",
        "",
        f"MITRE ATT&CK techniques: {_join(techniques)}",
        "",
        "Timeline:",
    ]
    lines += [f"  {entry}" for entry in timeline] or ["  not stated"]

    raw = incident.get("raw")
    if isinstance(raw, str) and raw.strip():
        lines += ["", "Excerpt of the original report:", raw.strip()[:RAW_EXCERPT_LIMIT]]
    return "\n".join(lines)


_PROMPT_HEAD = """You are an expert Cyber Security Incident Response Analyst writing for a Security Operations Center.

Analyze the incident below. Use ONLY the incident data provided. If something is not stated in the data, say "not stated in the data" instead of guessing. Do not invent IP addresses, hosts, hashes or techniques.

=== INCIDENT DATA ===
"""

_PLAYBOOK_RULES = """
The playbook excerpts above say what the company wants done. The incident data is the only source for facts about what happened.
Base the Mitigation and Best Practices sections on the playbook excerpts where they apply, and cite them like [KB1] or [KB2]. If no excerpt applies, write "No playbook applies" and use general best practice instead.
"""

_PROMPT_TAIL = """
Write the report in EXACTLY this format. Use these exact headers, each on its own line starting with '### ', and write nothing outside this format:

### Incident Summary
(2 to 4 sentences: what happened, to what, and when)

### Attack Type
(The type of attack, for example Phishing, Ransomware or Brute Force)

### Severity
(Low, Medium, High or Critical, then a one-line reason. Compare it with the severity reported by the source.)

### Root Cause
(What most likely caused the incident, citing indicators of compromise from the data)

### Explanation
(A plain-language explanation a non-expert could follow, including the business impact)

### Mitigation
(Numbered steps grouped as: Immediate containment, Eradication, Recovery)

### Best Practices
(Bulleted prevention measures)

### Disclaimer
(One short sentence saying this is an AI-generated analysis that a qualified security professional must review before any action is taken)
"""


def build_prompt(incident: dict, playbook_block: str = "") -> str:
    """The analysis prompt. `playbook_block` holds retrieved playbook excerpts, if there are any."""
    prompt = _PROMPT_HEAD + build_incident_facts(incident) + "\n=== END OF INCIDENT DATA ===\n"
    if playbook_block:
        prompt += "\n" + playbook_block + "\n" + _PLAYBOOK_RULES
    return prompt + _PROMPT_TAIL


# ------------------------------------------------------------------ parsing
_HEADER_RE = re.compile(r"^[ \t]*#{2,4}[ \t]*(.+?)[ \t]*:?[ \t]*$", re.MULTILINE)


def _canonical(header: str):
    cleaned = re.sub(r"[*_`:]", "", header).strip().lower()
    for name in SECTION_ORDER:
        if cleaned == name.lower():
            return name
    return None


def parse_sections(text: str) -> Dict[str, str]:
    """Split a '### Header' report into {section name: text}. Unknown headers stay inside the text."""
    found = [(m, _canonical(m.group(1))) for m in _HEADER_RE.finditer(text)]
    found = [(m, name) for m, name in found if name]
    sections: Dict[str, str] = {}
    for index, (match, name) in enumerate(found):
        end = found[index + 1][0].start() if index + 1 < len(found) else len(text)
        sections.setdefault(name, text[match.end():end].strip())
    return sections


def analyze(incident: dict, llm, model_name: str = "", playbook_block: str = "",
            playbook_sources=None) -> dict:
    """Run the analysis. Returns the sections plus the raw answer and some metadata."""
    answer = call_llm(llm, build_prompt(incident, playbook_block))
    sections = parse_sections(answer)
    format_ok = len(sections) >= 4
    if not format_ok:
        # The model ignored the format. Keep its answer instead of losing it.
        sections = {"Explanation": answer}
    return {
        "sections": sections,
        "raw": answer,
        "format_ok": format_ok,
        "model": model_name,
        "playbook_sources": list(playbook_sources or []),
        "generated_at": datetime.now(),
    }
