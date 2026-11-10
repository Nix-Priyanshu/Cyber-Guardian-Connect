"""The Connections tab."""
import uuid

import streamlit as st

from connectors import ConnectorError, RestApiConnector, build_connector
from ui.state import flash, get_database, remove_connection, sync_connection

MAX_UPLOAD_BYTES = 2 * 1024 * 1024


def _drop_connection(conn: dict):
    st.session_state.connections = [c for c in st.session_state.connections if c["id"] != conn["id"]]


def check_connection(conn: dict) -> bool:
    """Test the connection, show the result, and return True when it works."""
    try:
        ok, message = build_connector(conn).test_connection()
    except ConnectorError as exc:
        ok, message = False, str(exc)
    (st.success if ok else st.error)(message)
    return ok


def _save_and_sync(conn: dict) -> bool:
    st.session_state.connections.append(conn)
    try:
        count = sync_connection(conn)
    except ConnectorError as exc:
        _drop_connection(conn)
        st.error(str(exc))
        return False
    try:
        get_database().add_connection(st.session_state.user["id"], conn)
        flash(f"Connection '{conn['name']}' saved. {count} incident(s) synced.")
    except Exception as exc:                      # keep working even if saving fails
        flash(f"Connected, but the connection could not be saved for next time: {exc}", "warning")
    return True


def _render_rest_form():
    with st.form("add_rest"):
        name = st.text_input("Name", value="Simulated SOC Platform")
        base_url = st.text_input("Base URL", value="http://localhost:8000")
        api_key = st.text_input("API key", type="password", help="Sent as the X-API-Key header.")
        test_col, save_col = st.columns(2)
        test = test_col.form_submit_button("Test connection")
        save = save_col.form_submit_button("Save and sync", type="primary")

    if not (test or save):
        return
    if not (name.strip() and base_url.strip() and api_key.strip()):
        st.error("Enter a name, the base URL and the API key.")
        return
    conn = {"id": uuid.uuid4().hex[:8], "type": "rest", "name": name.strip(),
            "base_url": base_url.strip(), "api_key": api_key.strip(), "last_sync": None}
    if check_connection(conn) and save and _save_and_sync(conn):
        st.rerun()


def _render_file_form():
    with st.form("add_file"):
        name = st.text_input("Name", value="Uploaded report")
        uploaded = st.file_uploader("Incident report (.txt)", type=["txt"])
        save = st.form_submit_button("Save and sync", type="primary")

    if not save:
        return
    if not name.strip() or uploaded is None:
        st.error("Enter a name and choose a .txt report.")
        return
    if uploaded.size > MAX_UPLOAD_BYTES:
        st.error("That file is larger than 2 MB. Please upload a smaller report.")
        return
    conn = {"id": uuid.uuid4().hex[:8], "type": "file", "name": name.strip(),
            "filename": uploaded.name,
            "text": uploaded.getvalue().decode("utf-8", errors="replace"), "last_sync": None}
    if check_connection(conn) and _save_and_sync(conn):
        st.rerun()


def _render_add_connection():
    with st.expander("＋ Add a connection", expanded=not st.session_state.connections):
        kind = st.radio("Source type", ["REST API", "File upload"], horizontal=True)
        if kind == "REST API":
            _render_rest_form()
        else:
            _render_file_form()


def _render_card(conn: dict):
    count = len(st.session_state.incidents.get(conn["id"], []))
    with st.container(border=True):
        info_col, button_col = st.columns([3, 2])
        with info_col:
            st.markdown(f"**{conn['name']}**")
            st.caption(f"REST API at {conn['base_url']}" if conn["type"] == "rest"
                       else f"File: {conn['filename']}")
            synced = conn["last_sync"].strftime("%H:%M:%S") if conn["last_sync"] else "never"
            st.caption(f"{count} incident(s), last synced {synced}")
        with button_col:
            test_btn, sync_btn, remove_btn = st.columns(3)
            if test_btn.button("Test", key=f"test_{conn['id']}"):
                check_connection(conn)
            if sync_btn.button("Sync", key=f"sync_{conn['id']}"):
                try:
                    flash(f"'{conn['name']}' synced. {sync_connection(conn)} incident(s).")
                    st.rerun()
                except ConnectorError as exc:
                    st.error(str(exc))
            if remove_btn.button("Remove", key=f"remove_{conn['id']}"):
                remove_connection(conn)
                st.rerun()


def _render_demo_tools():
    rest = [c for c in st.session_state.connections if c["type"] == "rest"]
    if not rest:
        return
    with st.expander("Demo tools"):
        st.caption("Only for the simulated platform: makes it raise a new incident so you can "
                   "watch the dashboard react.")
        target = st.selectbox("Connection", options=range(len(rest)),
                              format_func=lambda n: rest[n]["name"], key="demo_target")
        if st.button("Create a new incident on the source"):
            conn = rest[target]
            try:
                created = RestApiConnector(conn["name"], conn["base_url"], conn["api_key"]).create_test_incident()
                st.success(f"The source raised {created.id}: {created.title}. "
                           "It will appear on the next refresh, or press Sync.")
            except ConnectorError as exc:
                st.error(str(exc))


def render_connections():
    st.subheader("Connections")
    st.caption("Link a web application or upload a report. Incoming data is converted to one common format.")
    _render_add_connection()
    if st.session_state.connections:
        st.markdown("**Your connections**")
        for conn in st.session_state.connections:
            _render_card(conn)
        _render_demo_tools()
