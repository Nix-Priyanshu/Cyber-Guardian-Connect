"""The AI Copilot tab: a chat about the connected incidents."""
import streamlit as st

from ai_analysis import AIError, get_llm
from copilot import STYLES, ask, search_query
from knowledge import format_playbook_block, sources_from_hits
from ui.kb_access import playbook_search
from ui.sidebar import get_ai_settings
from ui.state import all_incidents, get_database

MAX_STORED_MESSAGES = 40
ALL_INCIDENTS = "All incidents"

SUGGESTED_QUESTIONS = [
    "Which incidents are still active and how severe are they?",
    "Summarize the most serious incident in simple terms.",
    "Which IP addresses or domains appear in the incidents?",
    "What response actions have been taken so far?",
]


def _action_rows() -> list:
    try:
        return get_database().list_action_log(st.session_state.user["id"], None, 200)
    except Exception:
        return []


def _show_sources(sources: list):
    if not sources:
        return
    with st.expander(f"Sources used ({len(sources)})"):
        for source in sources:
            st.caption(f"{source['incident_id']}: {source['label']}")


def _answer(question: str, incidents: list, style: str, focus_key):
    settings = get_ai_settings()
    try:
        llm = get_llm(settings["provider"], settings["api_key"], settings["model"])
        with st.spinner("Searching your incidents and playbooks..."):
            hits, notice = playbook_search(search_query(question, st.session_state.chat))
            if notice:
                st.caption(notice)
            return ask(question, st.session_state.chat, incidents, _action_rows(), llm, style, focus_key,
                       format_playbook_block(hits), sources_from_hits(hits))
    except AIError as exc:
        st.error(str(exc))
        return None


def render_copilot():
    st.subheader("AI Copilot")
    st.caption("Ask questions about your connected incidents and your playbooks. The Copilot answers only from "
               "your data, shows which parts it used, and cannot take actions. Approve response actions on the Incident "
               "Analysis tab.")

    incidents = all_incidents()
    if not incidents:
        st.info("No incidents yet. Open the **Connections** tab and connect a source first.")
        return

    by_key = {i["_key"]: i for i in incidents}
    style_col, scope_col, clear_col = st.columns([2, 3, 1])
    style = style_col.selectbox("Answer style", list(STYLES), key="copilot_style")
    scope = scope_col.selectbox(
        "Focus on", [ALL_INCIDENTS] + list(by_key), key="copilot_scope",
        format_func=lambda k: k if k == ALL_INCIDENTS else f"{by_key[k]['id']}  {by_key[k]['title'][:60]}")
    clear_col.write("")
    if clear_col.button("Clear chat"):
        st.session_state.chat = []
        st.rerun()
    focus_key = None if scope == ALL_INCIDENTS else scope

    for message in st.session_state.chat:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            if message["role"] == "assistant":
                _show_sources(message.get("sources", []))

    if not st.session_state.chat:
        st.markdown("**Try asking:**")
        for number, suggestion in enumerate(SUGGESTED_QUESTIONS):
            if st.button(suggestion, key=f"suggest_{number}"):
                st.session_state.pending_question = suggestion

    question = st.chat_input("Ask about your incidents...") or st.session_state.pop("pending_question", None)
    if not question:
        return

    with st.chat_message("user"):
        st.markdown(question)
    result = _answer(question, incidents, style, focus_key)
    if result is None:
        return
    with st.chat_message("assistant"):
        st.markdown(result["answer"])
        _show_sources(result["sources"])

    st.session_state.chat += [
        {"role": "user", "content": question},
        {"role": "assistant", "content": result["answer"], "sources": result["sources"]},
    ]
    st.session_state.chat = st.session_state.chat[-MAX_STORED_MESSAGES:]
