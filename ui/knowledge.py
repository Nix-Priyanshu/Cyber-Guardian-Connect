"""The Knowledge Base tab: playbooks and policies that tell the app what to do."""
import glob
import os
import uuid

import streamlit as st

from ai_analysis import AIError
from knowledge import (
    MAX_FILE_BYTES, SUPPORTED_EXTENSIONS, KbChunk, chunk_document, embed_chunks, load_pages,
)
from ui.kb_access import get_embedder, get_kb_index
from ui.sidebar import get_embedding_settings
from ui.state import PROJECT_ROOT, flash, get_database

MAX_DOCUMENTS = 20
METHOD_LABELS = {"both": "keyword + meaning", "semantic": "meaning", "keyword": "keyword"}


def _add_document(name: str, data: bytes) -> str:
    """Read, chunk, embed (if a key is available) and store one document. Returns a message."""
    user_id = st.session_state.user["id"]
    database = get_database()
    existing = database.list_kb_documents(user_id)
    if len(existing) >= MAX_DOCUMENTS:
        raise AIError(f"The knowledge base is full ({MAX_DOCUMENTS} documents). Delete one first.")
    if any(d["name"] == name for d in existing):
        raise AIError(f"{name} is already in the knowledge base. Delete it first to replace it.")

    chunks = chunk_document("", name, load_pages(name, data))
    vectors, model, note = None, "", ""
    embedder = get_embedder()
    if embedder is None:
        note = " Saved for keyword search only, because no Gemini key is set."
    else:
        try:
            with st.spinner(f"Creating embeddings for {name}..."):
                vectors = embed_chunks(chunks, embedder)
            model = get_embedding_settings()["model"]
        except AIError as exc:
            note = f" Saved for keyword search only, because embeddings failed: {exc}"
    database.add_kb_document(
        user_id, uuid.uuid4().hex[:10], name,
        [{"index": c.index, "page": c.page, "text": c.text} for c in chunks], vectors, model)
    return f"{name}: {len(chunks)} chunks added.{note}"


def _embed_existing(doc_id: str):
    user_id = st.session_state.user["id"]
    embedder = get_embedder()
    if embedder is None:
        st.error("Enter a Gemini API key in the sidebar first.")
        return
    documents, _ = get_database().load_kb_documents(user_id)
    doc = next((d for d in documents if d["id"] == doc_id), None)
    if doc is None:
        return
    chunks = [KbChunk(doc_id, doc["name"], c["index"], c["page"], c["text"]) for c in doc["chunks"]]
    try:
        with st.spinner(f"Creating embeddings for {doc['name']}..."):
            vectors = embed_chunks(chunks, embedder)
    except AIError as exc:
        st.error(str(exc))
        return
    get_database().set_kb_vectors(user_id, doc_id, vectors, get_embedding_settings()["model"])
    flash(f"Embeddings created for {doc['name']}.")
    st.rerun()


def _render_upload():
    st.markdown("**Add documents**")
    uploaded = st.file_uploader("Playbooks, procedures or policies (PDF, TXT or MD)",
                                type=[e.lstrip(".") for e in SUPPORTED_EXTENSIONS], accept_multiple_files=True)
    add_col, sample_col = st.columns(2)
    if add_col.button("Add to knowledge base", type="primary", disabled=not uploaded):
        for file in uploaded:
            try:
                if file.size > MAX_FILE_BYTES:
                    raise AIError(f"{file.name} is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB.")
                flash(_add_document(file.name, file.getvalue()))
            except AIError as exc:
                st.error(f"{file.name}: {exc}")
        st.rerun()
    if sample_col.button("Load the 3 sample playbooks"):
        for path in sorted(glob.glob(os.path.join(PROJECT_ROOT, "sample_data", "playbooks", "*.md"))):
            try:
                with open(path, "rb") as handle:
                    flash(_add_document(os.path.basename(path), handle.read()))
            except AIError as exc:
                st.warning(str(exc))
        st.rerun()
    st.caption("Privacy: to create embeddings, the text of your documents is sent to Google (the same as in the "
               "first CyberGuardian project). Excerpts also go to your AI provider when they are used in an "
               "answer. Use sample or non-confidential documents for demos.")


def _render_documents():
    documents = get_database().list_kb_documents(st.session_state.user["id"])
    st.markdown(f"**Your documents ({len(documents)})**")
    if not documents:
        st.info("No documents yet. Add a playbook, or load the 3 samples, so the analysis and the Copilot "
                "can follow your company's procedures.")
        return
    for doc in documents:
        with st.container(border=True):
            info_col, button_col = st.columns([3, 2])
            with info_col:
                st.markdown(f"📄 **{doc['name']}**")
                status = (f"Meaning search on ({doc['embedding_model']})" if doc["embedded"]
                          else "Keyword search only (no embeddings yet)")
                st.caption(f"{doc['chunk_count']} chunks. {status}.")
            with button_col:
                embed_btn, delete_btn = st.columns(2)
                if not doc["embedded"] and embed_btn.button("Create embeddings", key=f"embed_{doc['id']}"):
                    _embed_existing(doc["id"])
                if delete_btn.button("Delete", key=f"delete_kb_{doc['id']}"):
                    get_database().delete_kb_document(st.session_state.user["id"], doc["id"])
                    st.rerun()


def _render_search():
    st.markdown("**Try a search**")
    st.caption("See how the two search methods work together. Meaning-based search finds related ideas even "
               "when the words differ. Keyword search finds exact terms.")
    with st.form("kb_search"):
        query = st.text_input("Ask something a playbook should answer",
                              placeholder="For example: how do we get systems back to normal after ransomware?")
        submitted = st.form_submit_button("Search")
    if not submitted or not query.strip():
        return
    index = get_kb_index()
    if index is None:
        st.info("Add a document first.")
        return
    outcome = index.search(query, 5, get_embedder())
    if outcome.notice:
        st.caption(outcome.notice)
    if not outcome.hits:
        st.info("Nothing in the knowledge base matches that question.")
        return
    for number, hit in enumerate(outcome.hits, start=1):
        place = f", page {hit.chunk.page}" if hit.chunk.page else ""
        with st.expander(f"{number}. {hit.chunk.doc_name}{place}  |  found by {METHOD_LABELS[hit.method]}",
                         expanded=number == 1):
            st.write(hit.chunk.text)


def render_knowledge():
    st.subheader("Knowledge base")
    st.caption("Incident data tells the app **what happened**. Playbooks and policies tell it **what to do**. "
               "Upload them here, and the AI analysis, the response-action suggestions and the Copilot will "
               "follow them and cite them.")
    _render_upload()
    st.divider()
    _render_documents()
    st.divider()
    _render_search()
