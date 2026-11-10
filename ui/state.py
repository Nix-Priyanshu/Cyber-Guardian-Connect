"""Session state shared by all tabs: connections, synced incidents, alerts and analyses."""
import os
from datetime import datetime
from pathlib import Path
from typing import List

import streamlit as st

from connectors import ConnectorError, build_connector
from dashboard_data import sort_incidents
from database import Database
from security import SecretBox, load_or_create_key

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def init_state():
    defaults = {
        "user": None,          # the logged-in user: {"id", "username", "role"}
        "connections": [],     # saved connection settings
        "incidents": {},       # connection id -> list of incident dicts (common format)
        "flash": [],           # messages shown once after a rerun
        "analyses": {},        # incident key -> AI analysis result
        "proposals": {},       # incident key -> proposed response actions
        "chat": [],            # AI Copilot conversation
        "kb_cache": None,      # the built playbook search index and the documents it was built from
        "alerts": [],          # incidents that appeared since the last look
        "last_refresh": None,  # when the live connections were last refreshed
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def read_secret(name: str) -> str:
    """Read a value from Streamlit secrets if the app has any. Never raises."""
    try:
        return str(st.secrets.get(name, "") or "")
    except Exception:
        return ""


@st.cache_resource
def get_database() -> Database:
    """One database object shared by all sessions."""
    data_dir = Path(os.environ.get("CYBERGUARDIAN_DATA_DIR", PROJECT_ROOT / "data"))
    key = load_or_create_key(data_dir, explicit=read_secret("CYBERGUARDIAN_SECRET_KEY"))
    return Database(data_dir / "cyberguardian.db", SecretBox(key))


def flash(message: str, level: str = "success"):
    st.session_state.flash.append((level, message))


def show_flash():
    for level, message in st.session_state.flash:
        (st.warning if level == "warning" else st.success)(message)
    st.session_state.flash = []


def sync_connection(conn: dict) -> int:
    """Fetch incidents through the connector, keep them, and note any new arrivals."""
    fetched = [incident.to_dict() for incident in build_connector(conn).fetch_incidents()]
    for incident in fetched:
        incident["conn_id"] = conn["id"]

    had_data = conn["id"] in st.session_state.incidents
    known_ids = {i["id"] for i in st.session_state.incidents.get(conn["id"], [])}
    st.session_state.incidents[conn["id"]] = fetched
    conn["last_sync"] = datetime.now()

    if had_data:
        st.session_state.alerts += [i for i in fetched if i["id"] not in known_ids]
    return len(fetched)


def refresh_live_connections() -> List[str]:
    """Re-sync every REST connection. Returns readable error messages for those that failed."""
    errors = []
    for conn in st.session_state.connections:
        if conn["type"] != "rest":
            continue
        try:
            sync_connection(conn)
        except ConnectorError as exc:
            errors.append(f"{conn['name']}: {exc}")
    st.session_state.last_refresh = datetime.now()
    return errors


def load_saved_connections(user_id: int):
    """After login: load the user's saved connections and sync them so the dashboard is ready."""
    connections, unreadable = get_database().list_connections(user_id)
    st.session_state.connections = connections
    st.session_state.incidents = {}
    for conn in connections:
        try:
            sync_connection(conn)
        except ConnectorError as exc:
            flash(f"Could not sync '{conn['name']}': {exc}", "warning")
    if unreadable:
        flash(f"{unreadable} saved connection(s) could not be read because the secret key changed.",
              "warning")


def logout():
    """Forget everything about this session, including any AI key typed in the sidebar."""
    st.session_state.clear()
    st.rerun()


def remove_connection(conn: dict):
    user = st.session_state.get("user")
    if user:
        get_database().delete_connection(user["id"], conn["id"])
    st.session_state.connections = [c for c in st.session_state.connections if c["id"] != conn["id"]]
    st.session_state.incidents.pop(conn["id"], None)


def all_incidents() -> List[dict]:
    """Every synced incident, newest first, each with a unique '_key'."""
    incidents = []
    for conn in st.session_state.connections:
        for incident in st.session_state.incidents.get(conn["id"], []):
            incidents.append({**incident, "_key": f"{conn['id']}:{incident['id']}"})
    return sort_incidents(incidents)


def pop_alerts() -> List[dict]:
    alerts, st.session_state.alerts = st.session_state.alerts, []
    return alerts
