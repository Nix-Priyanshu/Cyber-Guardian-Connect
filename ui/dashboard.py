"""
The Dashboard tab.

It shows the overall threat level, key numbers, indicators, ATT&CK techniques,
affected hosts and a timeline, all computed from the synced incidents (no AI
calls). The body runs as a Streamlit fragment, so with auto-refresh switched on
only this part re-runs every few seconds and pulls fresh data from the live
connections.
"""
from datetime import datetime

import pandas as pd
import streamlit as st

import dashboard_data as dd
from ui.state import all_incidents, pop_alerts, refresh_live_connections
from ui.style import severity_label, threat_badge


def _refresh_if_due(interval: int):
    """Fetch new data, but only when the timer says it is time (not on every click)."""
    last = st.session_state.last_refresh
    if last is None or (datetime.now() - last).total_seconds() >= interval * 0.9:
        for message in refresh_live_connections():
            st.warning(f"Could not refresh {message}")


def _incidents_table(incidents: list):
    frame = pd.DataFrame([{
        "ID": i["id"], "Title": i["title"], "Severity": severity_label(i["severity"]),
        "Status": i["status"] or "-", "Host": i["host"]["hostname"] or "-",
        "Created": i["created_at"], "Source": i["source"],
    } for i in incidents])
    st.dataframe(frame, hide_index=True)


def _top_ips_table(incidents: list):
    rows = [{"IP address": ip, "Incidents": count,
             "Scope": "Internal" if dd.is_private_ip(ip) else "External"}
            for ip, count in dd.top_indicators(incidents, "ips", 8)]
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True)
    else:
        st.caption("No IP addresses in the connected incidents.")


def _dashboard_body(auto_refresh: bool, interval: int):
    if auto_refresh:
        _refresh_if_due(interval)

    for new_incident in pop_alerts():
        st.toast(f"New {new_incident['severity']} incident: {new_incident['id']}, {new_incident['title']}",
                 icon="🚨")

    incidents = all_incidents()
    if not incidents:
        threat_badge("NO_DATA")
        st.info("Nothing to show yet. Open the **Connections** tab and connect a web application "
                "or upload a report.")
        return

    active = [i for i in incidents if dd.is_active(i)]
    counts = dd.severity_counts(incidents, active_only=True)

    # ---- status row
    badge_col, total_col, active_col, urgent_col = st.columns([1.6, 1, 1, 1])
    with badge_col:
        threat_badge(dd.overall_threat_level(incidents))
    total_col.metric("Incidents", len(incidents))
    active_col.metric("Active", len(active))
    urgent_col.metric("Critical or high (active)", counts["Critical"] + counts["High"])

    st.write("")
    critical_col, high_col, medium_col, low_col = st.columns(4)
    critical_col.metric("🔴 Critical", counts["Critical"])
    high_col.metric("🟠 High", counts["High"])
    medium_col.metric("🟡 Medium", counts["Medium"])
    low_col.metric("🔵 Low", counts["Low"])
    st.caption("Counts show active incidents only. Contained, resolved and closed incidents are left out.")

    # ---- incidents and indicators
    left, right = st.columns([1.6, 1])
    with left:
        st.markdown("**Incidents**")
        _incidents_table(incidents)
    with right:
        st.markdown("**Top IP addresses**")
        _top_ips_table(incidents)

    st.markdown("**Indicators seen across all incidents**")
    ip_col, domain_col, hash_col, cve_col, host_col = st.columns(5)
    ip_col.metric("External IPs", dd.external_ip_count(incidents))
    domain_col.metric("Domains", dd.unique_indicator_count(incidents, "domains"))
    hash_col.metric("File hashes", dd.unique_indicator_count(incidents, "hashes"))
    cve_col.metric("CVEs", dd.unique_indicator_count(incidents, "cves"))
    host_col.metric("Affected hosts", len(dd.host_summary(incidents)))

    # ---- techniques and hosts
    technique_col, hosts_col = st.columns(2)
    with technique_col:
        st.markdown("**MITRE ATT&CK techniques**")
        techniques = dd.technique_counts(incidents)
        if techniques:
            chart = pd.DataFrame(
                {"Incidents": [c for _, _, c in techniques]},
                index=[f"{tid} {name}".strip() for tid, name, _ in techniques],
            )
            st.bar_chart(chart, horizontal=True)
        else:
            st.caption("No ATT&CK techniques in the connected incidents.")
    with hosts_col:
        st.markdown("**Affected hosts**")
        hosts = dd.host_summary(incidents)
        if hosts:
            frame = pd.DataFrame(hosts)
            frame["Worst severity"] = frame["Worst severity"].map(severity_label)
            st.dataframe(frame, hide_index=True)
        else:
            st.caption("No host information in the connected incidents.")

    # ---- timeline of one incident
    st.markdown("**Attack timeline**")
    keys = [i["_key"] for i in incidents]
    by_key = {i["_key"]: i for i in incidents}
    chosen = st.selectbox("Incident", options=keys, key="dashboard_timeline_pick",
                          format_func=lambda k: f"{by_key[k]['id']}  {by_key[k]['title'][:70]}")
    timeline = by_key[chosen]["timeline"]
    if timeline:
        st.dataframe(pd.DataFrame(timeline).rename(columns={"time": "Time", "event": "Event"}),
                     hide_index=True)
    else:
        st.caption("This incident has no timeline.")

    refreshed = st.session_state.last_refresh
    if auto_refresh and refreshed:
        st.caption(f"Live: last refreshed {refreshed.strftime('%H:%M:%S')}, updates every {interval} seconds.")
    elif not auto_refresh:
        st.caption("Auto-refresh is off. Press Sync on the Connections tab to update.")


def render_dashboard():
    has_live_source = any(c["type"] == "rest" for c in st.session_state.connections)
    auto_refresh = bool(st.session_state.get("auto_refresh", True)) and has_live_source
    interval = int(st.session_state.get("refresh_seconds", 10))
    run_every = interval if auto_refresh else None
    st.fragment(run_every=run_every)(_dashboard_body)(auto_refresh, interval)
