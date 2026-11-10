"""Shared access to the playbook knowledge base for every tab that uses it."""
from typing import List, Optional, Tuple

import streamlit as st

from knowledge import GeminiEmbedder, KbChunk, KbHit, KnowledgeIndex
from ui.sidebar import get_embedding_settings
from ui.state import get_database


def get_embedder() -> Optional[GeminiEmbedder]:
    """The embedding model client, or None when no Gemini key is available."""
    settings = get_embedding_settings()
    return GeminiEmbedder(settings["api_key"], settings["model"]) if settings["api_key"] else None


def get_kb_index() -> Optional[KnowledgeIndex]:
    """The user's search index, rebuilt only when their documents change. None if they have none."""
    user_id = st.session_state.user["id"]
    documents = get_database().list_kb_documents(user_id)
    if not documents:
        st.session_state.kb_cache = None
        return None
    signature = tuple((d["id"], d["embedded"]) for d in documents)
    cache = st.session_state.get("kb_cache")
    if cache and cache["signature"] == signature:
        return cache["index"]

    loaded, _ = get_database().load_kb_documents(user_id)
    chunks: List[KbChunk] = []
    vectors = []
    for doc in loaded:
        for number, chunk in enumerate(doc["chunks"]):
            chunks.append(KbChunk(doc["id"], doc["name"], chunk["index"], chunk["page"], chunk["text"]))
            vectors.append(doc["vectors"][number] if doc["vectors"] is not None else None)
    index = KnowledgeIndex(chunks, vectors)
    st.session_state.kb_cache = {"signature": signature, "index": index}
    return index


def has_playbooks() -> bool:
    try:
        return bool(get_database().list_kb_documents(st.session_state.user["id"]))
    except Exception:
        return False


def playbook_search(query: str, k: int = 4) -> Tuple[List[KbHit], str]:
    """Hybrid search of the playbooks. Returns (hits, notice). Never raises: a problem gives no hits."""
    try:
        index = get_kb_index()
        if index is None:
            return [], ""
        outcome = index.search(query, k, get_embedder())
        return outcome.hits, outcome.notice
    except Exception as exc:
        return [], f"Playbook search failed: {exc}"
