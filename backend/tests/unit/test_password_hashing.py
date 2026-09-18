"""scrypt password hashing."""

import pytest

from app.core.config import Settings, get_settings
from app.core.security import (
    MAX_PASSWORD_BYTES,
    hash_password,
    needs_rehash,
    verify_password,
)

PASSWORD = "correct horse battery staple"


@pytest.fixture
def settings() -> Settings:
    return get_settings()


def test_hash_is_salted_so_equal_passwords_differ(settings: Settings) -> None:
    first = hash_password(PASSWORD, settings)
    second = hash_password(PASSWORD, settings)
    assert first != second
    assert verify_password(PASSWORD, first)
    assert verify_password(PASSWORD, second)


def test_hash_does_not_contain_the_password(settings: Settings) -> None:
    assert PASSWORD not in hash_password(PASSWORD, settings)


def test_wrong_password_is_rejected(settings: Settings) -> None:
    stored = hash_password(PASSWORD, settings)
    assert not verify_password(PASSWORD + "!", stored)
    assert not verify_password("", stored)


def test_tampered_or_malformed_hashes_never_verify(settings: Settings) -> None:
    stored = hash_password(PASSWORD, settings)
    scheme, params, salt, digest = stored.split("$")
    assert not verify_password(PASSWORD, f"{scheme}${params}${salt}${digest[:-2]}xx")
    assert not verify_password(PASSWORD, f"plaintext${params}${salt}${digest}")
    for broken in ["", "not-a-hash", "$$$", "scrypt$n=bad,r=8,p=1$aa$bb"]:
        assert not verify_password(PASSWORD, broken)


def test_unicode_passwords_work(settings: Settings) -> None:
    password = "पासवर्ड-मुंबई-2026"
    assert verify_password(password, hash_password(password, settings))


def test_oversized_password_is_refused(settings: Settings) -> None:
    with pytest.raises(ValueError, match="exceeds"):
        hash_password("x" * (MAX_PASSWORD_BYTES + 1), settings)


def test_needs_rehash_only_when_policy_is_stricter(settings: Settings) -> None:
    stored = hash_password(PASSWORD, settings)
    assert not needs_rehash(stored, settings)
    stricter = settings.model_copy(update={"SCRYPT_N": settings.SCRYPT_N * 4})
    assert needs_rehash(stored, stricter)
    assert needs_rehash("bcrypt$whatever$a$b", settings)


def test_production_default_cost_is_not_weak() -> None:
    """Tests run with a cheap cost; the shipped default must stay strong."""
    defaults = Settings.model_fields
    assert defaults["SCRYPT_N"].default >= 2**15
    assert defaults["PASSWORD_MIN_LENGTH"].default >= 12
