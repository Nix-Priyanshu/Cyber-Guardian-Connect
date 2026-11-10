"""Shows one incident in the common format. Used by the Incident Analysis tab."""
import pandas as pd
import streamlit as st

from ui.style import severity_label


def key_value_frame(values: dict) -> pd.DataFrame:
    rows = []
    for key, value in values.items():
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        rows.append({"Field": key.replace("_", " ").capitalize(), "Value": value or "-"})
    return pd.DataFrame(rows)


def render_incident_details(incident: dict):
    severity_col, status_col, actor_col, created_col = st.columns(4)
    severity_col.metric("Severity", severity_label(incident["severity"]))
    status_col.metric("Status", incident["status"] or "-")
    actor_col.metric("Threat actor", incident["threat_actor"] or "Unknown")
    created_col.metric("Created", incident["created_at"] or "-")
    st.write(incident["summary"])

    tab_asset, tab_ioc, tab_mitre, tab_time = st.tabs(
        ["Asset and network", "Indicators", "ATT&CK techniques", "Timeline"]
    )
    with tab_asset:
        left, right = st.columns(2)
        left.markdown("**Affected asset**")
        left.dataframe(key_value_frame(incident["host"]), hide_index=True)
        right.markdown("**Network**")
        right.dataframe(key_value_frame(incident["network"]), hide_index=True)
    with tab_ioc:
        found = False
        for label, values in incident["indicators"].items():
            if values:
                found = True
                st.markdown(f"**{label.capitalize()}** ({len(values)})")
                st.code("\n".join(values), language=None)
        if not found:
            st.caption("No indicators in this incident.")
    with tab_mitre:
        if incident["techniques"]:
            st.dataframe(pd.DataFrame(incident["techniques"]).rename(columns={"id": "ID", "name": "Technique"}),
                         hide_index=True)
        else:
            st.caption("No ATT&CK techniques in this incident.")
    with tab_time:
        if incident["timeline"]:
            st.dataframe(pd.DataFrame(incident["timeline"]).rename(columns={"time": "Time", "event": "Event"}),
                         hide_index=True)
        else:
            st.caption("No timeline in this incident.")
