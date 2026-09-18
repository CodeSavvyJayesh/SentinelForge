"""Access token creation and verification."""

import base64
import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import Settings, get_settings
from app.core.security import (
    JWT_ALGORITHM,
    JWT_AUDIENCE,
    JWT_ISSUER,
    InvalidTokenError,
    create_access_token,
    decode_access_token,
)


@pytest.fixture
def settings() -> Settings:
    return get_settings()


def make_token(settings: Settings, **overrides: object) -> str:
    payload = {
        "sub": "1",
        "role": "USER",
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        "jti": "abc123",
    }
    payload.update(overrides)
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=JWT_ALGORITHM)


def test_round_trip_returns_the_claims(settings: Settings) -> None:
    token, expires_at = create_access_token(user_id=7, role="ADMIN", settings=settings)
    claims = decode_access_token(token, settings)
    assert claims.user_id == 7
    assert claims.role == "ADMIN"
    assert claims.token_id
    assert abs((claims.expires_at - expires_at).total_seconds()) < 1


def test_each_token_has_a_unique_id(settings: Settings) -> None:
    first, _ = create_access_token(user_id=1, role="USER", settings=settings)
    second, _ = create_access_token(user_id=1, role="USER", settings=settings)
    assert decode_access_token(first, settings).token_id != (
        decode_access_token(second, settings).token_id
    )


def test_expired_token_is_rejected(settings: Settings) -> None:
    past = datetime.now(UTC) - timedelta(hours=2)
    token, _ = create_access_token(user_id=1, role="USER", settings=settings, now=past)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, settings)


def test_token_signed_with_another_key_is_rejected(settings: Settings) -> None:
    other = settings.model_copy(update={"JWT_SECRET": "a-completely-different-secret-key-value"})
    token, _ = create_access_token(user_id=1, role="USER", settings=other)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, settings)


def test_tampered_payload_is_rejected(settings: Settings) -> None:
    token = make_token(settings)
    header, payload, signature = token.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
    decoded["role"] = "ADMIN"
    forged = base64.urlsafe_b64encode(json.dumps(decoded).encode()).decode().rstrip("=")
    with pytest.raises(InvalidTokenError):
        decode_access_token(f"{header}.{forged}.{signature}", settings)


def test_unsigned_alg_none_token_is_rejected(settings: Settings) -> None:
    """The classic JWT attack: swap the algorithm for 'none' and drop the signature."""
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "sub": "1",
                    "role": "ADMIN",
                    "iss": JWT_ISSUER,
                    "aud": JWT_AUDIENCE,
                    "iat": 1,
                    "exp": 9999999999,
                    "jti": "x",
                }
            ).encode()
        )
        .decode()
        .rstrip("=")
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(f"{header}.{payload}.", settings)


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "someone-else"},
        {"aud": "another-api"},
    ],
)
def test_wrong_issuer_or_audience_is_rejected(settings: Settings, overrides: dict) -> None:
    with pytest.raises(InvalidTokenError):
        decode_access_token(make_token(settings, **overrides), settings)


def test_garbage_input_is_rejected(settings: Settings) -> None:
    for value in ["", "not.a.token", "a.b.c.d"]:
        with pytest.raises(InvalidTokenError):
            decode_access_token(value, settings)
