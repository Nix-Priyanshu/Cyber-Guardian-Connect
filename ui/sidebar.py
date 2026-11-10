"""Sidebar with AI settings and live-refresh controls."""
import streamlit as st

from ai_analysis import DEFAULT_MODELS
from knowledge import DEFAULT_EMBEDDING_MODEL
from ui.state import logout, read_secret

SECRET_NAMES = {"Gemini": "GEMINI_API_KEY", "Groq": "GROQ_API_KEY"}


def get_ai_settings() -> dict:
    """The provider, key and model chosen in the sidebar (a typed key wins over a secret)."""
    provider = st.session_state.get("provider", "Gemini")
    typed_key = (st.session_state.get(f"key_{provider}") or "").strip()
    model = (st.session_state.get(f"model_{provider}") or DEFAULT_MODELS[provider]).strip()
    return {"provider": provider, "api_key": typed_key or read_secret(SECRET_NAMES[provider]), "model": model}


def get_embedding_settings() -> dict:
    """The Gemini key and model used to create embeddings for the playbook knowledge base."""
    provider = st.session_state.get("provider", "Gemini")
    typed = st.session_state.get("key_Gemini") if provider == "Gemini" else st.session_state.get("embed_key")
    key = (typed or "").strip() or read_secret(SECRET_NAMES["Gemini"])
    model = (st.session_state.get("embed_model") or DEFAULT_EMBEDDING_MODEL).strip()
    return {"api_key": key, "model": model}


def render_sidebar(user: dict):
    with st.sidebar:
        st.markdown("## 🛡️ CyberGuardian Connect")
        st.markdown(f"Signed in as **{user['username']}**")
        st.caption(f"Role: {user['role']}")
        if st.button("Log out"):
            logout()
        st.divider()

        st.subheader("AI settings")
        provider = st.selectbox("AI provider", ["Gemini", "Groq"], key="provider",
                                help="Which service writes the incident analysis.")
        st.text_input(f"{provider} API key", type="password", key=f"key_{provider}",
                      placeholder="Paste your key here",
                      help="Kept only in this browser session. It is never saved.")
        st.text_input("Model name", value=DEFAULT_MODELS[provider], key=f"model_{provider}",
                      help="The exact model ID sent to the provider. Change it if the provider renames models.")
        if get_ai_settings()["api_key"]:
            st.success("API key ready")
        else:
            st.warning("Enter an API key to use the AI analysis.")

        st.divider()
        st.subheader("Playbook search")
        if provider == "Gemini":
            st.caption("Meaning-based search of your playbooks uses your Gemini key.")
        else:
            st.text_input("Gemini API key (embeddings only)", type="password", key="embed_key",
                          placeholder="Paste your Gemini key here",
                          help="Groq has no embeddings service, so playbook search uses Gemini for that step.")
        st.text_input("Embedding model", value=DEFAULT_EMBEDDING_MODEL, key="embed_model",
                      help="Change it if the provider renames or retires the model.")
        if get_embedding_settings()["api_key"]:
            st.success("Meaning-based playbook search is ready")
        else:
            st.info("No Gemini key yet: playbooks are searched by keywords only.")

        st.divider()
        st.subheader("Live updates")
        st.toggle("Auto-refresh the dashboard", value=True, key="auto_refresh",
                  help="Re-syncs your REST connections in the background. Uploaded files do not change.")
        st.slider("Refresh every (seconds)", min_value=5, max_value=60, value=10, step=5, key="refresh_seconds")
