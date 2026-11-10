"""
Security helpers for accounts and saved connections.

* Passwords are never stored. We store a salted PBKDF2-HMAC-SHA256 hash.
* Saved connection settings (URL, API key, uploaded report) are encrypted with
  Fernet (AES-128-CBC with an HMAC), so the database file alone is not enough
  to read them. The encryption key lives outside the database.
"""
import base64
import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

PBKDF2_ITERATIONS = 600_000     # OWASP's 2023 recommendation for PBKDF2-HMAC-SHA256
MIN_PASSWORD_LENGTH = 8
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
COMMON_PASSWORDS = {
    "password", "password1", "12345678", "123456789", "1234567890", "qwertyui", "qwerty123",
    "iloveyou", "admin123", "letmein1", "welcome1", "abc12345",
}


class AuthError(Exception):
    """A sign-up or login problem with a message that is safe to show to the user."""


class SecretError(Exception):
    """The encryption key is missing, invalid, or does not match the stored data."""


# ------------------------------------------------------------------ validation
def validate_username(username: str) -> str:
    username = (username or "").strip()
    if not USERNAME_RE.match(username):
        raise AuthError("Username must be 3 to 32 characters: letters, numbers, dot, dash or underscore.")
    return username


def validate_password(password: str, username: str = "") -> None:
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if password.lower() in COMMON_PASSWORDS or (username and password.lower() == username.lower()):
        raise AuthError("That password is too easy to guess. Choose a different one.")


# ------------------------------------------------------------------ passwords
def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Return 'pbkdf2_sha256$iterations$salt$hash' with a fresh random salt."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """Check a password against a stored hash in constant time. Never raises."""
    try:
        scheme, iterations, salt_b64, hash_b64 = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(hash_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, AttributeError):
        return False


# A hash of a random password, used so that "unknown user" takes as long as "wrong password".
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


# ------------------------------------------------------------------ encryption
class SecretBox:
    """Encrypts and decrypts short strings with one Fernet key."""

    def __init__(self, key: bytes):
        try:
            self._fernet = Fernet(key)
        except (ValueError, TypeError) as exc:
            raise SecretError("The secret key is not a valid Fernet key.") from exc

    def encrypt(self, text: str) -> str:
        return self._fernet.encrypt(text.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError) as exc:
            raise SecretError("Stored data could not be decrypted (wrong or changed key).") from exc


def load_or_create_key(data_dir: Path, explicit: Optional[str] = None) -> bytes:
    """
    Where the encryption key comes from, in order:
      1. the `explicit` value (for example from Streamlit secrets),
      2. the CYBERGUARDIAN_SECRET_KEY environment variable,
      3. a key file in the data folder, created on first run.
    """
    provided = (explicit or os.environ.get("CYBERGUARDIAN_SECRET_KEY") or "").strip()
    if provided:
        return provided.encode("ascii")

    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    key_file = data_dir / "secret.key"
    if key_file.exists():
        return key_file.read_bytes().strip()
    key = Fernet.generate_key()
    key_file.write_bytes(key)
    try:
        os.chmod(key_file, 0o600)      # owner only (no effect on Windows, harmless)
    except OSError:
        pass
    return key
