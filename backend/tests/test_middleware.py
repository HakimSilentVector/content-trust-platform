"""
Tests for the request-guarding middleware.

Two controls, both cost-DoS relevant (OWASP API4:2023 / LLM04):
  - TokenBucketRateLimiter: bounds request rate per client.
  - input_guard.check_text: rejects oversized/malformed input before any LLM call.

The rate-limiter tests use an INJECTED CLOCK so they are fully deterministic —
no sleeps, no flakiness. This is itself the testing best practice for time-based
security controls.

Run:  cd backend && python3 -m pytest tests/test_middleware.py -v
"""

import pytest

from middleware.rate_limit import TokenBucketRateLimiter, RateDecision
from middleware.input_guard import check_text, MAX_CHARS, MIN_CHARS


# ============================ RATE LIMITER =================================

class FakeClock:
    """Manually-advanced monotonic clock."""
    def __init__(self):
        self.t = 1000.0
    def __call__(self) -> float:
        return self.t
    def advance(self, secs: float):
        self.t += secs


def test_burst_up_to_capacity_then_blocked():
    clk = FakeClock()
    rl = TokenBucketRateLimiter(capacity=5, refill_per_sec=1.0, clock=clk)
    # 5 immediate requests allowed (burst == capacity).
    for i in range(5):
        d = rl.check("client-1")
        assert d.allowed, f"request {i} should be allowed"
    # 6th is blocked.
    d = rl.check("client-1")
    assert not d.allowed
    assert d.retry_after_sec > 0


def test_refill_over_time():
    clk = FakeClock()
    rl = TokenBucketRateLimiter(capacity=5, refill_per_sec=1.0, clock=clk)
    for _ in range(5):
        rl.check("c")
    assert not rl.check("c").allowed          # drained
    clk.advance(3)                            # 3 tokens refill
    assert rl.check("c").allowed
    assert rl.check("c").allowed
    assert rl.check("c").allowed
    assert not rl.check("c").allowed          # only 3 came back


def test_refill_never_exceeds_capacity():
    clk = FakeClock()
    rl = TokenBucketRateLimiter(capacity=5, refill_per_sec=1.0, clock=clk)
    rl.check("c")                             # 4 left
    clk.advance(10_000)                       # huge idle
    # Should cap at capacity, not overflow: exactly 5 allowed then block.
    allowed = sum(1 for _ in range(6) if rl.check("c").allowed)
    assert allowed == 5


def test_clients_are_isolated():
    clk = FakeClock()
    rl = TokenBucketRateLimiter(capacity=2, refill_per_sec=1.0, clock=clk)
    rl.check("alice"); rl.check("alice")
    assert not rl.check("alice").allowed      # alice drained
    assert rl.check("bob").allowed            # bob unaffected


def test_retry_after_is_accurate():
    clk = FakeClock()
    rl = TokenBucketRateLimiter(capacity=1, refill_per_sec=0.5, clock=clk)
    assert rl.check("c").allowed
    d = rl.check("c")
    assert not d.allowed
    # deficit 1 token at 0.5/sec => ~2s
    assert abs(d.retry_after_sec - 2.0) < 0.01


def test_empty_key_bucketed_as_anonymous():
    rl = TokenBucketRateLimiter(capacity=1, refill_per_sec=1.0)
    assert rl.check("").allowed
    assert not rl.check("").allowed           # same anonymous bucket


def test_invalid_config_rejected():
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(capacity=0, refill_per_sec=1.0)
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(capacity=5, refill_per_sec=0)


def test_reset_clears_bucket():
    rl = TokenBucketRateLimiter(capacity=1, refill_per_sec=0.001)
    rl.check("c")
    assert not rl.check("c").allowed
    rl.reset("c")
    assert rl.check("c").allowed


def test_cost_parameter_consumes_multiple_tokens():
    clk = FakeClock()
    rl = TokenBucketRateLimiter(capacity=10, refill_per_sec=1.0, clock=clk)
    d = rl.check("c", cost=7)
    assert d.allowed and d.remaining == 3
    assert not rl.check("c", cost=5).allowed   # only 3 left


# ============================ INPUT GUARD ==================================

def test_valid_text_passes():
    r = check_text("A perfectly normal sentence to analyze.")
    assert r.ok and r.reason is None
    assert r.cleaned == "A perfectly normal sentence to analyze."


def test_non_string_rejected():
    for bad in (None, 123, [], {}, b"bytes"):
        r = check_text(bad)
        assert not r.ok and r.reason == "type_not_string"


def test_too_long_rejected():
    r = check_text("x" * (MAX_CHARS + 1))
    assert not r.ok and r.reason == "too_long"


def test_at_limit_allowed():
    r = check_text("x" * MAX_CHARS)
    assert r.ok


def test_empty_and_whitespace_rejected():
    for empty in ("", "   ", "\t\n  \r"):
        r = check_text(empty)
        assert not r.ok and r.reason == "empty"


def test_control_chars_rejected():
    # NUL and other C0 controls (but tab/LF/CR are allowed).
    r = check_text("hello\x00world")
    assert not r.ok and r.reason == "control_chars"
    r2 = check_text("bell\x07here")
    assert not r2.ok and r2.reason == "control_chars"


def test_allowed_whitespace_controls_pass():
    r = check_text("line one\nline two\twith tab\r\n")
    assert r.ok


def test_reason_codes_are_safe_to_log():
    """Rejection reasons must be fixed machine codes, never echo user content."""
    r = check_text("secret data \x00 leak attempt")
    assert r.reason == "control_chars"
    assert "secret" not in (r.reason or "")     # content never in the reason


def test_guard_does_not_mutate_or_store(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = set(p.name for p in tmp_path.iterdir())
    check_text("some confidential business text")
    after = set(p.name for p in tmp_path.iterdir())
    assert before == after
