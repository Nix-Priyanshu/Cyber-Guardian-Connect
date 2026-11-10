"""Log in / sign up screen. The rest of the app is only shown once a user is signed in."""
from typing import Optional

import streamlit as st

from security import AuthError
from ui.state import get_database, load_saved_connections


def _start_session(user: dict):
    st.session_state.user = user
    with st.spinner("Loading your connections..."):
        load_saved_connections(user["id"])
    st.rerun()


def _login_form():
    with st.form("login"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Log in", type="primary")
    if submitted:
        try:
            user = get_database().authenticate(username, password)
        except AuthError as exc:
            st.error(str(exc))
            return
        _start_session(user)


def _signup_form():
    with st.form("signup"):
        username = st.text_input("Choose a username", help="3 to 32 characters: letters, numbers, . - _")
        password = st.text_input("Choose a password", type="password", help="At least 8 characters.")
        confirm = st.text_input("Repeat the password", type="password")
        submitted = st.form_submit_button("Create account", type="primary")
    if submitted:
        if password != confirm:
            st.error("The two passwords do not match.")
            return
        try:
            user = get_database().create_user(username, password)
        except AuthError as exc:
            st.error(str(exc))
            return
        _start_session(user)


def render_auth_gate() -> Optional[dict]:
    """Show the login screen unless someone is signed in. Returns the user, or None."""
    user = st.session_state.get("user")
    if user:
        return user

    st.title("🛡️ CyberGuardian Connect")
    st.caption("Sign in to open your connections, dashboard and analyses.")
    _, middle, _ = st.columns([1, 1.6, 1])
    with middle:
        login_tab, signup_tab = st.tabs(["Log in", "Sign up"])
        with login_tab:
            _login_form()
        with signup_tab:
            _signup_form()
        st.caption("Passwords are stored as salted hashes, and saved connection details are encrypted.")
    return None
