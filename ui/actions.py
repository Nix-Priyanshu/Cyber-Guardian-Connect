"""
Response actions section of the Incident Analysis tab.

Flow: the AI (or simple rules) proposes actions, a person reviews each one,
and only an approved action is sent to the connected platform. Every decision
is written to the audit log.
"""
from datetime import datetime

import pandas as pd
import streamlit as st

from ai_actions import ACTION_LABELS, propose_actions, rule_based_proposals
from ai_analysis import AIError, get_llm
from connectors import ConnectorError, RestApiConnector
from knowledge import format_playbook_block, incident_query
from ui.kb_access import playbook_search
from ui.sidebar import get_ai_settings
from ui.state import get_database, sync_connection

PRIORITY_ICONS = {"high": "🔴", "medium": "🟡", "low": "🔵"}
STATUS_TEXT = {"executed": "✅ Executed", "rejected": "🚫 Rejected", "failed": "⚠️ Failed"}


def _connection_for(incident: dict):
    return next((c for c in st.session_state.connections if c["id"] == incident.get("conn_id")), None)


def _log(incident: dict, conn, proposal: dict, decision: str, result: str, detail: str = ""):
    """Write to the audit log. A logging problem is shown but never blocks the analyst."""
    try:
        get_database().log_action(st.session_state.user["id"], {
            "incident_id": incident["id"], "connection_name": conn["name"] if conn else incident.get("source", ""),
            "action": proposal["action"], "target": proposal["target"], "proposed_by": proposal["source"],
            "decision": decision, "result": result, "detail": detail,
        })
    except Exception as exc:
        st.warning(f"The decision could not be written to the audit log: {exc}")


def _executed_pairs(incident: dict) -> set:
    """(action, target) pairs already carried out for this incident, so they are not suggested again."""
    try:
        rows = get_database().list_action_log(st.session_state.user["id"], incident["id"])
    except Exception:
        return set()
    return {(r["action"], r["target"]) for r in rows if r["result"] == "executed"}


def _suggest(incident: dict, use_ai: bool):
    dropped, playbooks = 0, []
    if use_ai:
        settings = get_ai_settings()
        try:
            llm = get_llm(settings["provider"], settings["api_key"], settings["model"])
            with st.spinner("Choosing response actions..."):
                hits, _ = playbook_search(incident_query(incident))
                playbooks = sorted({h.chunk.doc_name for h in hits})
                items, dropped = propose_actions(incident, llm, format_playbook_block(hits))
        except AIError as exc:
            st.error(str(exc))
            return
    else:
        items = rule_based_proposals(incident)
    done = _executed_pairs(incident)
    fresh = [p for p in items if (p["action"], p["target"]) not in done]
    st.session_state.proposals[incident["_key"]] = {
        "items": fresh, "dropped": dropped, "already_done": len(items) - len(fresh), "playbooks": playbooks}


def _approve(incident: dict, conn: dict, proposal: dict):
    user = st.session_state.user
    try:
        record = RestApiConnector(conn["name"], conn["base_url"], conn["api_key"]).send_action(
            incident["id"], proposal["action"], proposal["target"], requested_by=user["username"])
        proposal["status"] = "executed"
        proposal["detail"] = f"{conn['name']} recorded action #{record.get('id', '?')}"
        _log(incident, conn, proposal, "approved", "executed", proposal["detail"])
        try:
            sync_connection(conn)          # pick up the incident's new status
        except ConnectorError:
            pass
    except ConnectorError as exc:
        proposal["status"] = "failed"
        proposal["detail"] = str(exc)
        _log(incident, conn, proposal, "approved", "failed", str(exc))


def _reject(incident: dict, conn, proposal: dict):
    proposal["status"] = "rejected"
    _log(incident, conn, proposal, "rejected", "none")


def _render_proposal(incident: dict, conn, proposal: dict):
    can_execute = conn is not None and conn["type"] == "rest"
    with st.container(border=True):
        text_col, button_col = st.columns([3, 2])
        with text_col:
            st.markdown(f"{PRIORITY_ICONS[proposal['priority']]} **{ACTION_LABELS[proposal['action']]}**: "
                        f"`{proposal['target']}`")
            st.caption(f"{proposal['reason']} (suggested by {'AI' if proposal['source'] == 'ai' else 'rules'}, "
                       f"priority {proposal['priority']})")
        with button_col:
            if proposal["status"] == "proposed":
                if can_execute:
                    approve_col, reject_col = st.columns(2)
                    if approve_col.button("Approve", key=f"approve_{proposal['id']}", type="primary",
                                          help=f"Sends this action to {conn['name']}."):
                        _approve(incident, conn, proposal)
                        st.rerun()
                    if reject_col.button("Reject", key=f"reject_{proposal['id']}"):
                        _reject(incident, conn, proposal)
                        st.rerun()
                else:
                    st.caption("Advisory only: this incident came from an uploaded file, so there is no "
                               "platform to send the action to.")
            else:
                st.markdown(STATUS_TEXT[proposal["status"]])
                if proposal["detail"]:
                    st.caption(proposal["detail"])


def _render_history(incident: dict):
    try:
        rows = get_database().list_action_log(st.session_state.user["id"], incident["id"])
    except Exception:
        return
    if not rows:
        return
    with st.expander(f"Action history for {incident['id']} ({len(rows)})"):
        frame = pd.DataFrame([{
            "Time": datetime.fromisoformat(r["created_at"]).astimezone().strftime("%d %b %H:%M:%S"),
            "Action": ACTION_LABELS.get(r["action"], r["action"]), "Target": r["target"],
            "Decision": r["decision"].capitalize(), "Result": r["result"].capitalize(),
            "Suggested by": "AI" if r["proposed_by"] == "ai" else "Rules", "Details": r["detail"] or "-",
        } for r in rows])
        st.dataframe(frame, hide_index=True)


def render_actions(incident: dict):
    st.subheader("Response actions")
    st.caption("The AI suggests containment steps. Nothing is sent anywhere until you approve it, and every "
               "decision is logged. Suggestions are checked against the incident data, so they can only "
               "name IP addresses, hosts and accounts that appear in it.")
    conn = _connection_for(incident)

    ai_col, rules_col = st.columns(2)
    if ai_col.button("Suggest actions with AI", type="primary"):
        _suggest(incident, use_ai=True)
    if rules_col.button("Suggest actions without AI"):
        _suggest(incident, use_ai=False)

    stored = st.session_state.proposals.get(incident["_key"])
    if stored is None:
        st.caption("No suggestions yet for this incident.")
    else:
        if stored["dropped"]:
            st.caption(f"{stored['dropped']} suggestion(s) were dropped because they did not match "
                       "this incident's data.")
        if stored.get("playbooks"):
            st.caption("Playbook excerpts considered: " + ", ".join(stored["playbooks"]) + ".")
        if stored.get("already_done"):
            st.caption(f"{stored['already_done']} suggested action(s) were left out because you already "
                       "carried them out (see the action history).")
        if not stored["items"]:
            st.info("No new actions to recommend for this incident.")
        for proposal in stored["items"]:
            _render_proposal(incident, conn, proposal)

    _render_history(incident)
