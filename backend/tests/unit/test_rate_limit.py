"""In-memory rate limiter."""

import pytest

from app.core.rate_limit import InMemoryRateLimiter


def test_allows_up_to_the_limit_then_blocks() -> None:
    limiter = InMemoryRateLimiter(max_attempts=3, window_seconds=60)
    assert [limiter.hit("ip").allowed for _ in range(3)] == [True, True, True]
    blocked = limiter.hit("ip")
    assert not blocked.allowed
    assert blocked.retry_after_seconds > 0


def test_keys_are_independent() -> None:
    limiter = InMemoryRateLimiter(max_attempts=1, window_seconds=60)
    assert limiter.hit("a").allowed
    assert not limiter.hit("a").allowed
    assert limiter.hit("b").allowed


def test_window_expiry_allows_new_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = {"now": 1_000.0}
    monkeypatch.setattr("app.core.rate_limit.time.monotonic", lambda: clock["now"])
    limiter = InMemoryRateLimiter(max_attempts=2, window_seconds=60)
    assert limiter.hit("ip").allowed
    assert limiter.hit("ip").allowed
    assert not limiter.hit("ip").allowed
    clock["now"] += 61
    assert limiter.hit("ip").allowed


def test_reset_clears_a_key() -> None:
    limiter = InMemoryRateLimiter(max_attempts=1, window_seconds=60)
    limiter.hit("ip")
    limiter.reset("ip")
    assert limiter.hit("ip").allowed


def test_memory_is_bounded() -> None:
    limiter = InMemoryRateLimiter(max_attempts=5, window_seconds=60, max_keys=10)
    for index in range(100):
        limiter.hit(f"client-{index}")
    assert len(limiter._hits) <= 11
