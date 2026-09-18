"""Security primitives: password hashing, access tokens, refresh tokens, CSRF.

Design notes
------------
* **Passwords** use ``hashlib.scrypt`` (memory-hard KDF, listed by OWASP right
  after Argon2id). Hashes are stored in a self-describing format so the cost
  parameters can be raised later and old hashes upgraded on next login:
  ``scrypt$n=32768,r=8,p=2$<salt-b64>$<hash-b64>``.
* **Access tokens** are short-lived JWTs (HS256). The algorithm is a module
  constant, never configuration, so an attacker cannot force ``alg: none``
  or an algorithm confusion attack through the environment.
* **Refresh tokens** are opaque random strings. Only their SHA-256 hash is
  stored, so a database leak does not hand out valid sessions. They are sent
  to the browser in an httpOnly cookie, which JavaScript cannot read.
* **CSRF**: because the refresh token travels in a cookie, refresh/logout use
  the double-submit pattern — a random value is set in a readable cookie and
  must be echoed back in the ``X-CSRF-Token`` header.
"""

import base64
import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import jwt

from app.core.config import Settings

# Fixed on purpose: not configurable, so it cannot be downgraded.
JWT_ALGORITHM: Final[str] = "HS256"
JWT_ISSUER: Final[str] = "sentinelforge"
JWT_AUDIENCE: Final[str] = "sentinelforge-api"

SCRYPT_SCHEME: Final[str] = "scrypt"
SALT_BYTES: Final[int] = 16
KEY_BYTES: Final[int] = 32
REFRESH_TOKEN_BYTES: Final[int] = 32
CSRF_TOKEN_BYTES: Final[int] = 32

# scrypt reads the whole password into memory; cap the input so a huge body
# cannot be used for a denial-of-service attack.
MAX_PASSWORD_BYTES: Final[int] = 1024

REFRESH_COOKIE_NAME: Final[str] = "sf_refresh"
CSRF_COOKIE_NAME: Final[str] = "sf_csrf"
CSRF_HEADER_NAME: Final[str] = "X-CSRF-Token"


class InvalidTokenError(Exception):
    """Raised when an access token is missing, malformed, expired or forged."""


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


# --------------------------------------------------------------------------
# Passwords
# --------------------------------------------------------------------------


def hash_password(password: str, settings: Settings) -> str:
    """Hash a password with scrypt and return a self-describing string."""
    raw = _encode_password(password)
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.scrypt(
        raw,
        salt=salt,
        n=settings.SCRYPT_N,
        r=settings.SCRYPT_R,
        p=settings.SCRYPT_P,
        dklen=KEY_BYTES,
        maxmem=_maxmem(settings.SCRYPT_N, settings.SCRYPT_R, settings.SCRYPT_P),
    )
    params = f"n={settings.SCRYPT_N},r={settings.SCRYPT_R},p={settings.SCRYPT_P}"
    return f"{SCRYPT_SCHEME}${params}${_b64encode(salt)}${_b64encode(derived)}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Check a password against a stored hash. Never raises on bad input."""
    try:
        scheme, params, salt_b64, hash_b64 = stored_hash.split("$")
        if scheme != SCRYPT_SCHEME:
            return False
        values = dict(item.split("=") for item in params.split(","))
        n, r, p = int(values["n"]), int(values["r"]), int(values["p"])
        salt = _b64decode(salt_b64)
        expected = _b64decode(hash_b64)
        candidate = hashlib.scrypt(
            _encode_password(password),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
            maxmem=_maxmem(n, r, p),
        )
    except (ValueError, KeyError, TypeError):
        return False
    # Constant-time comparison: a timing difference would leak the hash.
    return hmac.compare_digest(candidate, expected)


def needs_rehash(stored_hash: str, settings: Settings) -> bool:
    """True when a stored hash uses weaker parameters than the current policy."""
    try:
        scheme, params, _, _ = stored_hash.split("$")
        if scheme != SCRYPT_SCHEME:
            return True
        values = dict(item.split("=") for item in params.split(","))
        return (
            int(values["n"]) < settings.SCRYPT_N
            or int(values["r"]) < settings.SCRYPT_R
            or int(values["p"]) < settings.SCRYPT_P
        )
    except (ValueError, KeyError):
        return True


def _encode_password(password: str) -> bytes:
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password exceeds {MAX_PASSWORD_BYTES} bytes")
    return raw


def _maxmem(n: int, r: int, p: int) -> int:
    """Memory limit passed to OpenSSL, with headroom over the actual need."""
    return int(128 * n * r * 1.5) + 1024 * 1024 * p


# --------------------------------------------------------------------------
# Access tokens (JWT)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AccessTokenClaims:
    """The claims SentinelForge trusts after a token has been verified."""

    user_id: int
    role: str
    token_id: str
    expires_at: datetime


def create_access_token(
    *, user_id: int, role: str, settings: Settings, now: datetime | None = None
) -> tuple[str, datetime]:
    """Create a signed access token. Returns the token and its expiry."""
    issued_at = now or datetime.now(UTC)
    expires_at = issued_at + timedelta(minutes=settings.ACCESS_TOKEN_TTL_MINUTES)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "role": role,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, expires_at


def decode_access_token(token: str, settings: Settings) -> AccessTokenClaims:
    """Verify a token's signature and claims.

    Raises ``InvalidTokenError`` for anything suspicious; the caller turns that
    into a 401 without telling the client which check failed.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[JWT_ALGORITHM],  # allow-list: blocks "none"/algorithm confusion
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
        user_id = int(payload["sub"])
        role = str(payload["role"])
        expires_at = datetime.fromtimestamp(int(payload["exp"]), tz=UTC)
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError) as exc:
        raise InvalidTokenError(str(exc)) from exc
    return AccessTokenClaims(
        user_id=user_id, role=role, token_id=str(payload["jti"]), expires_at=expires_at
    )


# --------------------------------------------------------------------------
# Refresh tokens and CSRF
# --------------------------------------------------------------------------


def generate_refresh_token() -> str:
    """A cryptographically random, opaque refresh token."""
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> str:
    """SHA-256 of a refresh token; only this is stored in the database.

    A fast hash is correct here (unlike for passwords): the token already has
    256 bits of entropy, so it cannot be brute-forced or guessed from a list.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(CSRF_TOKEN_BYTES)


def csrf_tokens_match(cookie_value: str | None, header_value: str | None) -> bool:
    """Double-submit check, in constant time."""
    if not cookie_value or not header_value:
        return False
    return hmac.compare_digest(cookie_value, header_value)
