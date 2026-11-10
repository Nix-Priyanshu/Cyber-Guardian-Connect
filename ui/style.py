"""Small shared visual helpers."""
import streamlit as st

# key -> (icon, label, text colour, background)
THREAT_LEVELS = {
    "CRITICAL": ("🔴", "Critical threat", "#ffb3bd", "rgba(196,20,40,0.30)"),
    "HIGH": ("🟠", "High threat", "#ffc39a", "rgba(196,74,20,0.28)"),
    "MEDIUM": ("🟡", "Medium threat", "#ffe08a", "rgba(196,138,20,0.26)"),
    "LOW": ("🔵", "Low threat", "#9fd0f0", "rgba(45,116,182,0.26)"),
    "UNKNOWN": ("⚪", "Severity unknown, needs review", "#d0d7de", "rgba(255,255,255,0.10)"),
    "CONTAINED": ("🟢", "All incidents contained", "#8fe3b5", "rgba(31,143,90,0.24)"),
    "NO_DATA": ("⚪", "No data connected", "#d0d7de", "rgba(255,255,255,0.08)"),
}

SEVERITY_ICONS = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Unknown": "⚪"}


def threat_badge(level_key: str):
    icon, label, colour, background = THREAT_LEVELS.get(level_key, THREAT_LEVELS["UNKNOWN"])
    st.markdown(
        f'<div style="padding:0.7rem 1rem;border-radius:10px;background:{background};color:{colour};'
        f'font-weight:600;font-size:1.05rem;border:1px solid rgba(255,255,255,0.12);">'
        f'{icon} {label}</div>',
        unsafe_allow_html=True,
    )


def severity_label(severity: str) -> str:
    return f"{SEVERITY_ICONS.get(severity, '⚪')} {severity}"
