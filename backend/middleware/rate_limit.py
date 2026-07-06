"""
Rate limiter (token-bucket, per-client-key).

Bounds request rate per client so a single scripted abuser cannot run up the
OpenAI bill. This is the primary economic-DoS control (OWASP LLM04 Unbounded
Consumption; classic web: missing rate limiting).

DESIGN CHOICES + TRADEOFFS
  - Token bucket (not fixed window): smooths bursts, allows a small burst up to
    `capacity` then refills at `refill_per_sec`. Fixed windows allow 2x bursts
    at the boundary; sliding-window log is more accurate but O(n) memory per
    client. Token bucket is O(1) memory/CPU per client — the right call for MVP.
  - In-memory store: fine for a single instance. TRADEOFF: does NOT share state
    across multiple backend instances. When you scale horizontally on Render,
    swap the store for Redis (same interface). Documented, not hidden.
  - Injectable clock: makes the limiter fully deterministic to test (no sleeps).

  KEYING: the caller supplies the client key. Prefer an auth/session id once you
  have accounts; until then, a hashed client IP. NEVER key on submitted content.

  ABUSE NOTE: IP keying is evadable via rotation (proxies, botnets). It raises
  the cost of abuse; it does not eliminate it. Layer with per-endpoint global
  ceilings and billing-side spend alerts (see Advanced Considerations).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    remaining: int
    retry_after_sec: float   # 0 when allowed


class TokenBucketRateLimiter:
    """Thread-safe in-memory token-bucket limiter.

    capacity        : max burst (tokens)
    refill_per_sec  : sustained rate (tokens per second)
    clock           : injectable time source (defaults to monotonic)
    """

    def __init__(
        self,
        capacity: int = 10,
        refill_per_sec: float = 0.2,   # ~12 requests/min sustained
        clock: Callable[[], float] | None = None,
    ) -> None:
        if capacity <= 0 or refill_per_sec <= 0:
            raise ValueError("capacity and refill_per_sec must be positive")
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        import time
        self._clock = clock or time.monotonic
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _refill(self, b: _Bucket, now: float) -> None:
        elapsed = now - b.last_refill
        if elapsed > 0:
            b.tokens = min(self.capacity, b.tokens + elapsed * self.refill_per_sec)
            b.last_refill = now

    def check(self, key: str, cost: float = 1.0) -> RateDecision:
        """Attempt to consume `cost` tokens for `key`. Returns a decision.
        Does not sleep or block."""
        if not key:
            key = "anonymous"
        now = self._clock()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(tokens=float(self.capacity), last_refill=now)
                self._buckets[key] = b
            self._refill(b, now)

            if b.tokens >= cost:
                b.tokens -= cost
                return RateDecision(allowed=True,
                                    remaining=int(b.tokens),
                                    retry_after_sec=0.0)

            deficit = cost - b.tokens
            retry = deficit / self.refill_per_sec
            return RateDecision(allowed=False,
                                remaining=int(b.tokens),
                                retry_after_sec=round(retry, 2))

    def reset(self, key: str) -> None:
        with self._lock:
            self._buckets.pop(key, None)

    def active_clients(self) -> int:
        with self._lock:
            return len(self._buckets)
