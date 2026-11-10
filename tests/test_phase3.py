"""
Phase 3 tests: password hashing, encryption at rest, accounts, lockout and
per-user isolation of saved connections.
Run from the project root:  python -m unittest discover -s tests -v
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from cryptography.fernet import Fernet  # noqa: E402

import database as database_module  # noqa: E402
from database import Database  # noqa: E402
from security import (  # noqa: E402
    AuthError, SecretBox, SecretError, hash_password, load_or_create_key,
    validate_password, validate_username, verify_password,
)

STRONG = "correct-horse-battery"
SECRET_KEY_TEXT = "sk-very-secret-api-key-12345"


class PasswordTests(unittest.TestCase):
    def test_hash_and_verify(self):
        stored = hash_password(STRONG, iterations=1000)
        self.assertTrue(stored.startswith("pbkdf2_sha256$1000$"))
        self.assertNotIn(STRONG, stored)
        self.assertTrue(verify_password(STRONG, stored))
        self.assertFalse(verify_password("wrong-password", stored))

    def test_same_password_gets_different_hashes(self):
        self.assertNotEqual(hash_password(STRONG, 1000), hash_password(STRONG, 1000))

    def test_verify_never_raises_on_garbage(self):
        for bad in ("", "nonsense", "a$b$c$d", "pbkdf2_sha256$x$y$z", None):
            self.assertFalse(verify_password("x", bad))

    def test_validation(self):
        self.assertEqual(validate_username("  alice_01 "), "alice_01")
        for bad in ("ab", "has space", "semi;colon", "x" * 33, ""):
            with self.assertRaises(AuthError):
                validate_username(bad)
        validate_password(STRONG, "alice")
        for bad, user in (("short", ""), ("password", ""), ("Alice2026x", "alice2026x")):
            with self.assertRaises(AuthError):
                validate_password(bad, user)


class EncryptionTests(unittest.TestCase):
    def test_round_trip_and_wrong_key(self):
        box = SecretBox(Fernet.generate_key())
        token = box.encrypt(SECRET_KEY_TEXT)
        self.assertNotIn(SECRET_KEY_TEXT, token)
        self.assertEqual(box.decrypt(token), SECRET_KEY_TEXT)
        with self.assertRaises(SecretError):
            SecretBox(Fernet.generate_key()).decrypt(token)

    def test_tampering_is_detected(self):
        box = SecretBox(Fernet.generate_key())
        token = box.encrypt("hello")
        with self.assertRaises(SecretError):
            box.decrypt(token[:-4] + "AAAA")

    def test_invalid_key(self):
        with self.assertRaises(SecretError):
            SecretBox(b"not a key")

    def test_key_file_is_created_once_and_reused(self):
        with tempfile.TemporaryDirectory() as folder:
            os.environ.pop("CYBERGUARDIAN_SECRET_KEY", None)
            first = load_or_create_key(Path(folder))
            self.assertEqual(first, load_or_create_key(Path(folder)))
            self.assertTrue((Path(folder) / "secret.key").exists())

    def test_explicit_key_wins(self):
        with tempfile.TemporaryDirectory() as folder:
            key = Fernet.generate_key().decode()
            self.assertEqual(load_or_create_key(Path(folder), explicit=key), key.encode())
            self.assertFalse((Path(folder) / "secret.key").exists())


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = Fernet.generate_key()
        self.path = Path(self.tmp.name) / "test.db"
        self.db = Database(self.path, SecretBox(self.key))
        # make hashing fast for the tests that create many users
        self._orig = database_module.hash_password
        database_module.hash_password = lambda p: hash_password(p, iterations=1000)
        self.addCleanup(lambda: setattr(database_module, "hash_password", self._orig))

    def make_user(self, name="alice", password=STRONG):
        return self.db.create_user(name, password)

    def rest_conn(self, cid="c1", name="SOC"):
        return {"id": cid, "type": "rest", "name": name, "base_url": "http://localhost:8000",
                "api_key": SECRET_KEY_TEXT, "last_sync": None}

    # ---- accounts
    def test_sign_up_and_log_in(self):
        user = self.make_user()
        self.assertEqual(user["role"], "analyst")
        again = self.db.authenticate("alice", STRONG)
        self.assertEqual(again["id"], user["id"])
        self.assertEqual(self.db.authenticate("ALICE", STRONG)["id"], user["id"])   # case-insensitive

    def test_duplicate_username_rejected_ignoring_case(self):
        self.make_user("alice")
        with self.assertRaises(AuthError):
            self.make_user("Alice")

    def test_unknown_user_and_wrong_password_look_the_same(self):
        self.make_user()
        messages = set()
        for name, password in (("alice", "wrong-password-1"), ("nobody", "whatever-123")):
            with self.assertRaises(AuthError) as ctx:
                self.db.authenticate(name, password)
            messages.add(str(ctx.exception))
        self.assertEqual(messages, {"Invalid username or password."})

    def test_lockout_after_repeated_failures(self):
        self.make_user()
        for _ in range(database_module.MAX_FAILED_ATTEMPTS):
            with self.assertRaises(AuthError):
                self.db.authenticate("alice", "wrong-password-1")
        with self.assertRaises(AuthError) as ctx:
            self.db.authenticate("alice", STRONG)          # even the right password is refused
        self.assertIn("Too many failed attempts", str(ctx.exception))

    def test_lockout_expires_and_success_resets(self):
        self.make_user()
        for _ in range(database_module.MAX_FAILED_ATTEMPTS):
            with self.assertRaises(AuthError):
                self.db.authenticate("alice", "wrong-password-1")
        past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        with sqlite3.connect(self.path) as raw:
            raw.execute("UPDATE users SET locked_until = ?", (past,))
        self.assertEqual(self.db.authenticate("alice", STRONG)["username"], "alice")
        with sqlite3.connect(self.path) as raw:
            self.assertEqual(raw.execute("SELECT failed_attempts, locked_until FROM users").fetchone(), (0, None))

    def test_password_is_not_stored_in_plain_text(self):
        self.make_user()
        raw = self.path.read_bytes()
        self.assertNotIn(STRONG.encode(), raw)
        self.assertIn(b"pbkdf2_sha256", raw)

    # ---- connections
    def test_connection_round_trip(self):
        user = self.make_user()
        self.db.add_connection(user["id"], self.rest_conn())
        file_conn = {"id": "c2", "type": "file", "name": "Report", "filename": "r.txt",
                     "text": "Incident ID: X-1", "last_sync": None}
        self.db.add_connection(user["id"], file_conn)
        connections, unreadable = self.db.list_connections(user["id"])
        self.assertEqual(unreadable, 0)
        self.assertEqual([c["id"] for c in connections], ["c1", "c2"])
        self.assertEqual(connections[0]["api_key"], SECRET_KEY_TEXT)
        self.assertEqual(connections[1]["text"], "Incident ID: X-1")
        self.assertIsNone(connections[0]["last_sync"])

    def test_secrets_are_encrypted_on_disk(self):
        user = self.make_user()
        self.db.add_connection(user["id"], self.rest_conn())
        raw = self.path.read_bytes()
        self.assertNotIn(SECRET_KEY_TEXT.encode(), raw)
        self.assertNotIn(b"localhost:8000", raw)
        self.assertIn(b"SOC", raw)      # the display name stays readable so lists work

    def test_users_cannot_see_or_delete_each_others_connections(self):
        alice, bob = self.make_user("alice"), self.make_user("bobby", "another-strong-pw")
        self.db.add_connection(alice["id"], self.rest_conn("a1"))
        self.assertEqual(self.db.list_connections(bob["id"]), ([], 0))
        self.assertFalse(self.db.delete_connection(bob["id"], "a1"))
        self.assertEqual(len(self.db.list_connections(alice["id"])[0]), 1)
        self.assertTrue(self.db.delete_connection(alice["id"], "a1"))
        self.assertEqual(self.db.list_connections(alice["id"]), ([], 0))

    def test_wrong_key_reports_unreadable_connections(self):
        user = self.make_user()
        self.db.add_connection(user["id"], self.rest_conn())
        other = Database(self.path, SecretBox(Fernet.generate_key()))
        self.assertEqual(other.list_connections(user["id"]), ([], 1))

    def test_deleting_a_user_removes_their_connections(self):
        user = self.make_user()
        self.db.add_connection(user["id"], self.rest_conn())
        with sqlite3.connect(self.path) as raw:
            raw.execute("PRAGMA foreign_keys = ON")
            raw.execute("DELETE FROM users WHERE id = ?", (user["id"],))
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM connections").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
