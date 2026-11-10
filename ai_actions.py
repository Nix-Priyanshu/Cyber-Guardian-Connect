"""
Response actions: proposing them safely.

The AI suggests actions such as blocking an IP address, isolating a host or
disabling an account. A language model can make things up, so nothing it says
is trusted blindly: every proposal is checked against the incident's own data,
and anything that does not match is dropped. Only the actions and targets that
this module allows can ever reach the analyst's approval screen.

Nothing here executes an action. Execution happens only after a human approves.
"""
import json
import re
import uuid
from typing import Dict, List, Tuple

from ai_analysis import AIError, build_incident_facts, call_llm
from dashboard_data import is_private_ip

ACTION_LABELS = {
    "block_ip": "Block IP address",
    "isolate_host": "Isolate host",
    "disable_account": "Disable user account",
}
PRIORITIES = ("high", "medium", "low")
MAX_PROPOSALS = 6
_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def allowed_targets(incident: dict) -> Dict[str, List[str]]:
    """
    The only targets an action may name, taken from the incident itself.
    Only EXTERNAL IP addresses may be blocked, so a proposal can never cut off an internal server.
    """
    host = incident.get("host") or {}
    net = incident.get("network") or {}
    candidates = list((incident.get("indicators") or {}).get("ips") or [])
    candidates += list(net.get("destination_ips") or [])
    candidates.append(net.get("source_ip", ""))
    external = [ip for ip in dict.fromkeys(candidates)
                if ip and _IP_RE.match(ip) and not is_private_ip(ip)]
    return {
        "block_ip": external,
        "isolate_host": [host["hostname"]] if host.get("hostname") else [],
        "disable_account": [host["username"]] if host.get("username") else [],
    }


def _new_proposal(action: str, target: str, reason: str, priority: str, source: str) -> dict:
    return {
        "id": uuid.uuid4().hex[:8], "action": action, "target": target,
        "reason": reason.strip()[:300], "priority": priority if priority in PRIORITIES else "medium",
        "source": source, "status": "proposed", "detail": "",
    }


# ------------------------------------------------------------------ AI proposals
_PROMPT = """You are an incident response analyst deciding which containment actions to recommend.

=== INCIDENT DATA ===
{facts}
=== END OF INCIDENT DATA ===
{playbook}
You may recommend ONLY these actions, and ONLY with the exact targets listed here (copy them exactly):
{allowed}

Rules:
- Recommend an action only when the incident data gives clear evidence for it.
- Never invent a target. If nothing fits an action type, leave that type out.
- Give each action a short reason that points to evidence in the data.
- If a company playbook excerpt above calls for one of these actions, recommend it (using an allowed target) and name the playbook in the reason, for example "Ransomware playbook: isolate the host".
- Recommend at most {limit} actions. An empty list is a valid answer.

Answer with ONLY a JSON array and nothing else, for example:
[{{"action": "block_ip", "target": "203.0.113.5", "reason": "Command and control address seen in the traffic", "priority": "high"}}]
The action must be one of: block_ip, isolate_host, disable_account. The priority must be high, medium or low.
"""


def build_action_prompt(incident: dict, playbook_block: str = "") -> str:
    targets = allowed_targets(incident)
    lines = [f"- {action} ({ACTION_LABELS[action]}): {', '.join(values) if values else 'no valid targets'}"
             for action, values in targets.items()]
    return _PROMPT.format(facts=build_incident_facts(incident), allowed="\n".join(lines), limit=MAX_PROPOSALS,
                          playbook=f"\n{playbook_block}\n" if playbook_block else "")


def _extract_json_array(text: str):
    """Find the JSON array in the model's answer, even if it is wrapped in text or code fences."""
    cleaned = re.sub(r"```(?:json)?", "", text)
    start, end = cleaned.find("["), cleaned.rfind("]")
    if start == -1 or end <= start:
        raise AIError("The AI did not return a list of actions. Try again.")
    try:
        data = json.loads(cleaned[start:end + 1])
    except ValueError as exc:
        raise AIError("The AI's list of actions could not be read. Try again.") from exc
    if not isinstance(data, list):
        raise AIError("The AI did not return a list of actions. Try again.")
    return data


def parse_proposals(text: str, incident: dict) -> Tuple[List[dict], int]:
    """
    Turn the model's answer into validated proposals.
    Returns (proposals, number dropped because they did not match the incident).
    """
    allowed = {action: {t.lower(): t for t in targets} for action, targets in allowed_targets(incident).items()}
    proposals, seen, dropped = [], set(), 0
    for item in _extract_json_array(text):
        if not isinstance(item, dict):
            dropped += 1
            continue
        action = str(item.get("action", "")).strip().lower()
        target = str(item.get("target", "")).strip()
        exact = allowed.get(action, {}).get(target.lower())
        if exact is None:
            dropped += 1
            continue
        if (action, exact) in seen:
            continue
        seen.add((action, exact))
        proposals.append(_new_proposal(action, exact, str(item.get("reason", "")) or "No reason given.",
                                       str(item.get("priority", "")).lower(), "ai"))
    order = {p: n for n, p in enumerate(PRIORITIES)}
    proposals.sort(key=lambda p: order[p["priority"]])
    return proposals[:MAX_PROPOSALS], dropped


def propose_actions(incident: dict, llm, playbook_block: str = "") -> Tuple[List[dict], int]:
    """Ask the model for actions, then keep only the ones the incident data supports."""
    return parse_proposals(call_llm(llm, build_action_prompt(incident, playbook_block)), incident)


# ------------------------------------------------------------------ rule-based fallback
def rule_based_proposals(incident: dict) -> List[dict]:
    """
    Simple, explainable suggestions that need no AI, so the feature still works
    without an API key. They follow only what the incident data says.
    """
    targets = allowed_targets(incident)
    severe = incident.get("severity") in ("Critical", "High")
    technique_ids = {t["id"].split(".")[0] for t in incident.get("techniques") or []}
    proposals = []
    for ip in targets["block_ip"]:
        proposals.append(_new_proposal("block_ip", ip, "External address listed as an indicator in this incident.",
                                       "high" if severe else "medium", "rules"))
    for host in targets["isolate_host"]:
        if severe:
            proposals.append(_new_proposal("isolate_host", host, f"The incident severity is {incident['severity']}.",
                                           "high", "rules"))
    for user in targets["disable_account"]:
        if severe or technique_ids & {"T1078", "T1110", "T1003"}:
            proposals.append(_new_proposal("disable_account", user,
                                           "The incident involves credential or account abuse.", "high", "rules"))
    return proposals[:MAX_PROPOSALS]
