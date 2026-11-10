"""
CyberGuardian Connect

Connect a security web application (or upload a report), watch a live
dashboard, get an AI analysis of any incident, and download a PDF report.

Run:  streamlit run app.py
"""
import streamlit as st

st.set_page_config(page_title="CyberGuardian Connect", page_icon="🛡️", layout="wide")

from ui.analysis import render_analysis          # noqa: E402  (after set_page_config)
from ui.auth import render_auth_gate             # noqa: E402
from ui.connections import render_connections    # noqa: E402
from ui.copilot import render_copilot            # noqa: E402
from ui.dashboard import render_dashboard        # noqa: E402
from ui.knowledge import render_knowledge        # noqa: E402
from ui.sidebar import render_sidebar            # noqa: E402
from ui.state import init_state, show_flash      # noqa: E402

init_state()
user = render_auth_gate()
if user is None:
    st.stop()          # nothing else is shown until someone is signed in
render_sidebar(user)

st.title("CyberGuardian Connect")
show_flash()

tab_dashboard, tab_analysis, tab_copilot, tab_knowledge, tab_connections = st.tabs(
    ["📊 Dashboard", "🔍 Incident Analysis", "💬 AI Copilot", "📚 Knowledge Base", "🔌 Connections"]
)
with tab_dashboard:
    render_dashboard()
with tab_analysis:
    render_analysis()
with tab_copilot:
    render_copilot()
with tab_knowledge:
    render_knowledge()
with tab_connections:
    render_connections()
