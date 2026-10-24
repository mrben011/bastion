"""Cryptographic helpers: password hashing, session tokens, TOTP, field encryption."""
import hashlib
import hmac
import re
import secrets
import time

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet

from .config import get_settings

_hasher = PasswordHasher()  # argon2id with library defaults
# Verified against when the account does not exist, so timing does not reveal valid emails.
_DUMMY_HASH = _hasher.hash("bastion-dummy-password-for-timing")

_COMMON = {
    "password1234", "passwordpassword", "123456789012", "qwertyuiop12", "letmein123456",
    "administrator", "welcome12345", "changeme1234", "iloveyou12345",
}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def password_problems(password: str, email: str = "") -> list[str]:
    problems = []
    if len(password) < 12:
        problems.append("must be at least 12 characters")
    if len(password) > 128:
        problems.append("must be at most 128 characters")
    if password.lower() in _COMMON or len(set(password)) < 5:
        problems.append("is too common or too repetitive")
    local = email.split("@")[0].lower() if email else ""
    if local and len(local) >= 4 and local in password.lower():
        problems.append("must not contain your email name")
    return problems


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Only the hash of a session token is stored, so a database leak does not yield live sessions."""
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _fernet() -> Fernet:
    return Fernet(get_settings().field_encryption_key.encode())


def encrypt_field(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_field(value: str) -> str:
    return _fernet().decrypt(value.encode()).decode()


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="Bastion")


def verify_totp(secret: str, code: str, last_step: int | None) -> int | None:
    """Return the matched time step, or None. A step can be used once (replay protection)."""
    if not re.fullmatch(r"\d{6}", code or ""):
        return None
    totp = pyotp.TOTP(secret)
    now = time.time()
    for offset in (-1, 0, 1):
        t = now + offset * totp.interval
        if hmac.compare_digest(totp.at(t), code):
            step = int(t // totp.interval)
            if last_step is not None and step <= last_step:
                return None
            return step
    return None
