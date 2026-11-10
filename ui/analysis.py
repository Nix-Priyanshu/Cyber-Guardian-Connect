"""The Incident Analysis tab."""
import streamlit as st

from ai_analysis import AIError, analyze, get_llm
from knowledge import format_playbook_block, incident_query, sources_from_hits
from report_pdf import build_pdf_report
from ui.actions import render_actions
from ui.incident_view import render_incident_details
from ui.kb_access import has_playbooks, playbook_search
from ui.sidebar import get_ai_settings
from ui.state import all_incidents

SECTION_ICONS = {
    "Incident Summary": "📝", "Attack Type": "🎯", "Severity": "🚨", "Root Cause": "🔍",
    "Explanation": "💡", "Mitigation": "🛠️", "Best Practices": "✅", "Disclaimer": "⚠️",
}


def _run_analysis(incident: dict):
    settings = get_ai_settings()
    try:
        llm = get_llm(settings["provider"], settings["api_key"], settings["model"])
        with st.spinner(f"Analyzing {incident['id']} with {settings['model']}..."):
            hits, notice = playbook_search(incident_query(incident))
            result = analyze(incident, llm, settings["model"], format_playbook_block(hits),
                             sources_from_hits(hits))
            result["playbook_notice"] = notice
    except AIError as exc:
        st.error(str(exc))
        return
    st.session_state.analyses[incident["_key"]] = result


def _render_playbook_sources(result: dict):
    sources = result.get("playbook_sources") or []
    if result.get("playbook_notice"):
        st.caption(result["playbook_notice"])
    if sources:
        with st.expander(f"Playbook excerpts used ({len(sources)})"):
            for source in sources:
                place = f", page {source['page']}" if source.get("page") else ""
                st.markdown(f"**[{source['ref']}] {source['doc']}{place}** (found by {source['method']} search)")
                st.caption(source["text"])
    elif not has_playbooks():
        st.caption("Tip: add playbooks on the Knowledge Base tab so the mitigation steps follow your "
                   "company's procedures.")


def _render_result(incident: dict, result: dict):
    st.subheader("AI analysis")
    if not result["format_ok"]:
        st.warning("The model did not follow the report format, so its answer is shown as one block. "
                   "Try again, or pick a different model in the sidebar.")
    sections = result["sections"]
    left, right = st.columns(2)
    for index, name in enumerate(SECTION_ICONS):
        if name not in sections and result["format_ok"]:
            body = "_Not included in the analysis._"
        elif name not in sections:
            continue
        else:
            body = sections[name]
        with (left if index % 2 == 0 else right):
            with st.container(border=True):
                st.markdown(f"**{SECTION_ICONS[name]} {name}**")
                st.write(body)
    st.caption(f"Generated {result['generated_at'].strftime('%d %b %Y, %H:%M')} using {result['model'] or 'the selected model'}.")
    _render_playbook_sources(result)

    try:
        pdf_bytes = build_pdf_report(incident, sections, result["model"], result.get("playbook_sources"))
    except Exception as exc:                       # never let a PDF problem break the page
        st.error(f"The PDF report could not be created: {exc}")
        return
    st.download_button(
        "Download PDF report", data=pdf_bytes, mime="application/pdf",
        file_name=f"incident_report_{incident['id']}.pdf", type="primary",
    )


def render_analysis():
    st.subheader("Incident analysis")
    incidents = all_incidents()
    if not incidents:
        st.info("No incidents yet. Open the **Connections** tab and connect a source first.")
        return

    by_key = {i["_key"]: i for i in incidents}
    chosen = st.selectbox("Choose an incident", options=list(by_key), key="analysis_pick",
                          format_func=lambda k: f"{by_key[k]['id']}  {by_key[k]['title'][:80]}")
    incident = by_key[chosen]

    render_incident_details(incident)
    st.divider()

    result = st.session_state.analyses.get(chosen)
    button_label = "Run the analysis again" if result else "Analyze with AI"
    if st.button(button_label, type="primary"):
        _run_analysis(incident)
        result = st.session_state.analyses.get(chosen)
    if result:
        _render_result(incident, result)
    else:
        st.caption("The AI reads this incident's data and writes a summary, root cause, mitigation "
                   "steps and best practices. The provider and key are set in the sidebar.")

    st.divider()
    render_actions(incident)
