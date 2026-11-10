"""
SQLite storage for user accounts and each user's saved connections.

Every connection function takes a user id and filters on it, so one user can
never read or delete another user's connections.
"""
import base64
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np

from security import (
    DUMMY_HASH, AuthError, SecretBox, SecretError, hash_password,
    validate_password, validate_username, verify_password,
)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'analyst',
    created_at      TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT
);
CREATE TABLE IF NOT EXISTS connections (
    id           TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    type         TEXT NOT NULL,
    config_enc   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_connections_user ON connections(user_id);
CREATE TABLE IF NOT EXISTS action_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    incident_id     TEXT NOT NULL,
    connection_name TEXT NOT NULL,
    action          TEXT NOT NULL,
    target          TEXT NOT NULL,
    proposed_by     TEXT NOT NULL,
    decision        TEXT NOT NULL,
    result          TEXT NOT NULL,
    detail          TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_log_user ON action_log(user_id, incident_id);
CREATE TABLE IF NOT EXISTS kb_documents (
    id              TEXT PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    chunk_count     INTEGER NOT NULL,
    embedded        INTEGER NOT NULL DEFAULT 0,
    embedding_model TEXT NOT NULL DEFAULT '',
    payload_enc     TEXT NOT NULL,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kb_documents_user ON kb_documents(user_id);
"""

# Everything except these keys is treated as secret and stored encrypted.
_PLAIN_KEYS = {"id", "name", "type", "last_sync"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Database:
    def __init__(self, path: Path, secrets: SecretBox):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.secrets = secrets
        with closing(self._connect()) as db:
            db.executescript(SCHEMA)
            db.commit()

    def _connect(self) -> sqlite3.Connection:
        # One short-lived connection per operation keeps this safe across Streamlit's threads.
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        return db

    # ------------------------------------------------------------ users
    @staticmethod
    def _user_dict(row) -> dict:
        return {"id": row["id"], "username": row["username"], "role": row["role"]}

    def create_user(self, username: str, password: str, role: str = "analyst") -> dict:
        username = validate_username(username)
        validate_password(password, username)
        password_hash = hash_password(password)
        try:
            with closing(self._connect()) as db:
                cursor = db.execute(
                    "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                    (username, password_hash, role, _now().isoformat()),
                )
                db.commit()
                return {"id": cursor.lastrowid, "username": username, "role": role}
        except sqlite3.IntegrityError:
            raise AuthError("That username is already taken.")

    def authenticate(self, username: str, password: str) -> dict:
        """
        Return the user on success. Raises AuthError otherwise.
        The message is the same for an unknown user and a wrong password, and both
        take similar time, so the form does not reveal which usernames exist.
        After too many wrong passwords the account is locked for a few minutes.
        """
        generic = AuthError("Invalid username or password.")
        username = (username or "").strip()
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if row is None:
                verify_password(password or "", DUMMY_HASH)
                raise generic

            locked_until = row["locked_until"]
            if locked_until and datetime.fromisoformat(locked_until) > _now():
                minutes = int((datetime.fromisoformat(locked_until) - _now()).total_seconds() // 60) + 1
                raise AuthError(f"Too many failed attempts. Try again in about {minutes} minute(s).")

            if verify_password(password or "", row["password_hash"]):
                db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (row["id"],))
                db.commit()
                return self._user_dict(row)

            attempts = row["failed_attempts"] + 1
            lock = None
            if attempts >= MAX_FAILED_ATTEMPTS:
                lock = (_now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                attempts = 0
            db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                       (attempts, lock, row["id"]))
            db.commit()
            raise generic

    # ------------------------------------------------------------ connections
    def add_connection(self, user_id: int, conn: dict) -> None:
        secret_part = {k: v for k, v in conn.items() if k not in _PLAIN_KEYS}
        with closing(self._connect()) as db:
            db.execute(
                "INSERT INTO connections (id, user_id, name, type, config_enc, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (conn["id"], user_id, conn["name"], conn["type"],
                 self.secrets.encrypt(json.dumps(secret_part)), _now().isoformat()),
            )
            db.commit()

    def list_connections(self, user_id: int) -> Tuple[List[dict], int]:
        """Return (connections, number that could not be decrypted)."""
        connections, unreadable = [], 0
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT * FROM connections WHERE user_id = ? ORDER BY created_at", (user_id,)
            ).fetchall()
        for row in rows:
            try:
                config = json.loads(self.secrets.decrypt(row["config_enc"]))
            except (SecretError, ValueError):
                unreadable += 1
                continue
            connections.append({"id": row["id"], "name": row["name"], "type": row["type"],
                                **config, "last_sync": None})
        return connections, unreadable

    def delete_connection(self, user_id: int, conn_id: str) -> bool:
        with closing(self._connect()) as db:
            cursor = db.execute("DELETE FROM connections WHERE id = ? AND user_id = ?", (conn_id, user_id))
            db.commit()
            return cursor.rowcount > 0

    def get_user(self, user_id: int) -> Optional[dict]:
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return self._user_dict(row) if row else None

    # ------------------------------------------------------------ audit log of response actions
    def log_action(self, user_id: int, entry: dict) -> None:
        """
        Record a decision about a proposed action.
        decision: 'approved' or 'rejected'.  result: 'executed', 'failed' or 'none'.
        """
        with closing(self._connect()) as db:
            db.execute(
                "INSERT INTO action_log (user_id, incident_id, connection_name, action, target, proposed_by, "
                "decision, result, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, entry["incident_id"], entry.get("connection_name", ""), entry["action"], entry["target"],
                 entry.get("proposed_by", ""), entry["decision"], entry.get("result", "none"),
                 str(entry.get("detail", ""))[:500], _now().isoformat()),
            )
            db.commit()

    def list_action_log(self, user_id: int, incident_id: Optional[str] = None, limit: int = 100) -> List[dict]:
        """A user's own decisions, newest first, optionally for one incident."""
        query = "SELECT * FROM action_log WHERE user_id = ?"
        params: list = [user_id]
        if incident_id:
            query += " AND incident_id = ?"
            params.append(incident_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with closing(self._connect()) as db:
            rows = db.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------ playbook knowledge base
    def _pack_kb(self, chunks: List[dict], vectors: Optional[np.ndarray]) -> str:
        """Chunk text and embeddings are stored together, encrypted, as one blob."""
        payload = {"chunks": chunks, "dim": 0, "vectors": None}
        if vectors is not None and len(vectors):
            matrix = np.asarray(vectors, dtype=np.float32)
            payload["dim"] = int(matrix.shape[1])
            payload["vectors"] = base64.b64encode(matrix.tobytes()).decode("ascii")
        return self.secrets.encrypt(json.dumps(payload))

    def _unpack_kb(self, token: str) -> Tuple[List[dict], Optional[np.ndarray]]:
        payload = json.loads(self.secrets.decrypt(token))
        chunks = payload["chunks"]
        vectors = None
        if payload.get("vectors"):
            flat = np.frombuffer(base64.b64decode(payload["vectors"]), dtype=np.float32)
            vectors = flat.reshape(len(chunks), payload["dim"]).copy()
        return chunks, vectors

    def add_kb_document(self, user_id: int, doc_id: str, name: str, chunks: List[dict],
                        vectors: Optional[np.ndarray] = None, embedding_model: str = "") -> None:
        """chunks: [{'index', 'page', 'text'}]. vectors: one row per chunk, or None (keyword search only)."""
        with closing(self._connect()) as db:
            db.execute(
                "INSERT INTO kb_documents (id, user_id, name, chunk_count, embedded, embedding_model, "
                "payload_enc, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (doc_id, user_id, name, len(chunks), 1 if vectors is not None else 0,
                 embedding_model if vectors is not None else "", self._pack_kb(chunks, vectors),
                 _now().isoformat()),
            )
            db.commit()

    def list_kb_documents(self, user_id: int) -> List[dict]:
        """Names and status only (nothing is decrypted)."""
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT id, name, chunk_count, embedded, embedding_model, created_at FROM kb_documents "
                "WHERE user_id = ? ORDER BY created_at", (user_id,)).fetchall()
        return [dict(row) for row in rows]

    def load_kb_documents(self, user_id: int) -> Tuple[List[dict], int]:
        """Return (documents with their chunks and vectors, number that could not be decrypted)."""
        documents, unreadable = [], 0
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM kb_documents WHERE user_id = ? ORDER BY created_at",
                              (user_id,)).fetchall()
        for row in rows:
            try:
                chunks, vectors = self._unpack_kb(row["payload_enc"])
            except (SecretError, ValueError, KeyError):
                unreadable += 1
                continue
            documents.append({"id": row["id"], "name": row["name"], "chunks": chunks, "vectors": vectors,
                              "embedding_model": row["embedding_model"]})
        return documents, unreadable

    def set_kb_vectors(self, user_id: int, doc_id: str, vectors: np.ndarray, embedding_model: str) -> bool:
        """Add or replace a document's embeddings (for example after a key was added later)."""
        with closing(self._connect()) as db:
            row = db.execute("SELECT payload_enc FROM kb_documents WHERE id = ? AND user_id = ?",
                             (doc_id, user_id)).fetchone()
            if row is None:
                return False
            chunks, _ = self._unpack_kb(row["payload_enc"])
            db.execute("UPDATE kb_documents SET payload_enc = ?, embedded = 1, embedding_model = ? "
                       "WHERE id = ? AND user_id = ?",
                       (self._pack_kb(chunks, vectors), embedding_model, doc_id, user_id))
            db.commit()
            return True

    def delete_kb_document(self, user_id: int, doc_id: str) -> bool:
        with closing(self._connect()) as db:
            cursor = db.execute("DELETE FROM kb_documents WHERE id = ? AND user_id = ?", (doc_id, user_id))
            db.commit()
            return cursor.rowcount > 0
