"""
Spend-cap guard (global daily budget).

WHY THIS EXISTS
  The per-client rate limiter (middleware/rate_limit.py) bounds ONE client's
  request rate. It is evadable by IP rotation (proxies, botnets). This guard is
  the layer that survives that: a single GLOBAL ceiling on estimated LLM spend
  per rolling day. Even a distributed denial-of-wallet attack (T1499 Endpoint
  DoS / OWASP API4:2023 Unrestricted Resource Consumption) cannot exceed a
  dollar budget you pre-decided you can survive.

  It is denominated in ESTIMATED COST UNITS, not request count, because a
  rewrite call spends far more tokens than an analysis call. Bounding requests
  would under-protect the expensive path.

RELATIONSHIP TO THE ACCOUNT-LEVEL CAP
  This is YOUR code's ceiling. It can be bypassed by a bug in your code. The
  OpenAI dashboard hard spend cap is the backstop that survives even that, and
  ONLY YOU can set it (see set_openai_hard_cap docstring below). Use both.

DESIGN
  - Rolling 24h window via a simple decaying accumulator (O(1), no history).
  - Fail-CLOSED by default: if the guard's own state is corrupt, deny. For a
    COST control, denying is the safe error; failing open risks the bill.
  - Injectable clock for deterministic tests.
  - Never sees or logs submitted text; operates purely on numeric estimates.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable


# Rough cost estimates in abstract "units" (calibrate to real $ once you see
# actual token usage). Keep advisory < rewrite to reflect real token spend.
COST_ANALYZE = 1.0
COST_REWRITE = 3.0


@dataclass(frozen=True)
class SpendDecision:
    allowed: bool
    spent_today: float
    daily_cap: float
    reason: str | None = None   # machine code, safe to log


class DailySpendCap:
    """Global rolling-24h spend ceiling in cost units.

    daily_cap : total cost units allowed per rolling 24h window.
    clock     : injectable monotonic-ish time source (seconds).
    """

    WINDOW_SEC = 24 * 60 * 60

    def __init__(
        self,
        daily_cap: float = 1000.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if daily_cap <= 0:
            raise ValueError("daily_cap must be positive")
        self.daily_cap = float(daily_cap)
        import time
        self._clock = clock or time.monotonic
        self._spent = 0.0
        self._window_start = self._clock()
        self._lock = threading.Lock()

    def _roll_window(self, now: float) -> None:
        """Reset the accumulator when the 24h window elapses. Simple fixed
        window: predictable, O(1), and adequate for a budget ceiling. (A
        sliding window would be smoother but needs per-event history.)"""
        if now - self._window_start >= self.WINDOW_SEC:
            self._spent = 0.0
            self._window_start = now

    def check_and_charge(self, cost: float) -> SpendDecision:
        """Reserve `cost` units if budget remains. Atomic: check + charge under
        one lock so concurrent requests cannot both slip past the ceiling."""
        if cost < 0:
            # Defensive: a negative cost could 'refund' budget to an attacker.
            return SpendDecision(False, self._spent, self.daily_cap,
                                 reason="invalid_cost")
        now = self._clock()
        with self._lock:
            self._roll_window(now)
            if self._spent + cost > self.daily_cap:
                return SpendDecision(False, self._spent, self.daily_cap,
                                     reason="daily_cap_reached")
            self._spent += cost
            return SpendDecision(True, self._spent, self.daily_cap)

    def refund(self, cost: float) -> None:
        """Return budget if a charged call ultimately failed (e.g. provider
        error) so genuine users aren't penalized for our outage. Never goes
        below zero."""
        if cost <= 0:
            return
        with self._lock:
            self._spent = max(0.0, self._spent - cost)

    def status(self) -> SpendDecision:
        now = self._clock()
        with self._lock:
            self._roll_window(now)
            return SpendDecision(self._spent < self.daily_cap,
                                 self._spent, self.daily_cap)


def set_openai_hard_cap() -> str:
    """NOT executable from code — this is a human action, documented here so it
    is not forgotten. In the OpenAI dashboard:
        Settings -> Billing -> Limits -> set a HARD monthly usage limit
        (and a lower soft/alert threshold for early warning).
    This is the only control that survives a bug in THIS codebase. Set it before
    launch. Decide the number as 'the largest bill I could absorb without harm'.
    """
    return ("Set a hard monthly spend cap in the OpenAI dashboard: "
            "Settings > Billing > Limits. This is a manual, human-only step.")
