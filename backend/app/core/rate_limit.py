"""Rate limiting.

Phase 2 ships a simple in-memory sliding window, which is enough for a single
backend process and keeps the stack small. It is written against a Protocol so
a Redis-backed limiter can replace it later (needed as soon as more than one
worker process runs) without touching the endpoints.

Limitation, stated plainly: counters live in one process, so two workers each
allow the configured number of attempts, and restarting the server clears them.
"""

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: int


class RateLimiter(Protocol):
    def hit(self, key: str) -> RateLimitDecision:
        """Record one attempt for ``key`` and say whether it is allowed."""

    def reset(self, key: str) -> None: ...


class InMemoryRateLimiter:
    """Sliding-window limiter: at most ``max_attempts`` per ``window_seconds``."""

    def __init__(self, *, max_attempts: int, window_seconds: int, max_keys: int = 10_000) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str) -> RateLimitDecision:
        now = time.monotonic()
        window_start = now - self.window_seconds
        with self._lock:
            self._evict_if_needed()
            attempts = self._hits[key]
            while attempts and attempts[0] < window_start:
                attempts.popleft()
            if len(attempts) >= self.max_attempts:
                retry_after = max(1, int(attempts[0] + self.window_seconds - now) + 1)
                return RateLimitDecision(False, 0, retry_after)
            attempts.append(now)
            return RateLimitDecision(True, self.max_attempts - len(attempts), 0)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def _evict_if_needed(self) -> None:
        """Drop empty buckets, then the oldest keys, so memory cannot grow forever."""
        if len(self._hits) <= self.max_keys:
            return
        for key in [key for key, hits in self._hits.items() if not hits]:
            del self._hits[key]
        while len(self._hits) > self.max_keys:
            self._hits.pop(next(iter(self._hits)))
