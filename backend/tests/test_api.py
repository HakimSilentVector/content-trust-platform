"""
Integration tests for the /analyze pipeline and the spend-cap guard.

These test the WIRING: that the route chains guard -> rate limit -> spend cap
-> engines -> composer in the right order, rejects at the right stages, and
never lets the advisory layer or an outage corrupt the deterministic response.

The app runs WITHOUT an OPENAI_API_KEY here, so advisory_engine is None and the
deterministic path is exercised directly — proving the service is useful before
any key is configured, and that no network is touched in tests.

Run:  cd backend && python3 -m pytest tests/test_api.py tests/test_spend_cap.py -v
"""

import os
import pytest

# Ensure no key -> deterministic-only path, no network.
os.environ.pop("OPENAI_API_KEY", None)
# Exercise the app in its DEVELOPMENT profile: enables the localhost CORS
# fallback and the /docs routes. Production (ENV unset/"production") is the
# locked-down default; that fail-safe posture is intentional and separately
# asserted by test_cors_blocks_unlisted_origin.
os.environ["ENV"] = "development"

from fastapi.testclient import TestClient
import main
from middleware.spend_cap import DailySpendCap


client = TestClient(main.app)


@pytest.fixture(autouse=True)
def reset_state():
    """Reset shared singletons between tests so limits don't bleed across."""
    main.rate_limiter._buckets.clear()
    main.spend_cap._spent = 0.0
    yield


# ============================ /analyze pipeline ============================

def test_cors_allows_configured_origin():
    """A configured origin gets an allow header back."""
    allowed = main.ALLOWED_ORIGINS[0] if main.ALLOWED_ORIGINS else "http://localhost:3000"
    r = client.post("/analyze", json={"text": "a normal sentence here."},
                    headers={"Origin": allowed})
    assert r.headers.get("access-control-allow-origin") == allowed


def test_cors_blocks_unlisted_origin():
    """An evil origin must NOT receive an allow header (no wildcard leakage)."""
    r = client.post("/analyze", json={"text": "a normal sentence here."},
                    headers={"Origin": "https://evil.example.com"})
    # Starlette omits the allow-origin header entirely for disallowed origins.
    assert r.headers.get("access-control-allow-origin") != "https://evil.example.com"
    assert r.headers.get("access-control-allow-origin") != "*"


def test_health_ok():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["advisory_available"] is False   # no key in test env


def test_analyze_happy_path_deterministic_only():
    r = client.post("/analyze", json={"text": "Maria shipped the service to 12,000 users in March."})
    assert r.status_code == 200
    body = r.json()
    assert 0 <= body["composite_score"] <= 100
    assert body["advisory_available"] is False        # degrades cleanly, no key
    assert "metrics" in body and len(body["metrics"]) == 7
    assert body["request_id"]
    assert r.headers.get("X-Request-ID")


def test_analyze_is_reproducible_over_http():
    payload = {"text": "The rollout held at 99.97% uptime through the quarter."}
    a = client.post("/analyze", json=payload).json()
    b = client.post("/analyze", json=payload).json()
    # Deterministic numbers identical across requests (request_id differs).
    assert a["composite_score"] == b["composite_score"]
    assert a["metrics"] == b["metrics"]
    assert a["request_id"] != b["request_id"]


# --- Input guard fires BEFORE any expensive work ---------------------------

def test_empty_text_rejected_400():
    r = client.post("/analyze", json={"text": "   "})
    assert r.status_code == 400
    assert r.json()["reason"] == "empty"


def test_oversized_text_rejected_400():
    r = client.post("/analyze", json={"text": "x" * 20001})
    assert r.status_code == 400
    assert r.json()["reason"] == "too_long"


def test_control_chars_rejected_400():
    r = client.post("/analyze", json={"text": "hello\x00world padding here"})
    assert r.status_code == 400
    assert r.json()["reason"] == "control_chars"


def test_error_response_never_echoes_submitted_text():
    """A rejection must not reflect the user's content back (reason codes only)."""
    secret = "TOPSECRET_PAYLOAD_\x00_leak"
    r = client.post("/analyze", json={"text": secret})
    assert "TOPSECRET_PAYLOAD" not in r.text


# --- Rate limiting ----------------------------------------------------------

def test_rate_limit_fires_after_capacity():
    # capacity=10 in main; 11th from same client should 429.
    payload = {"text": "a normal sentence to analyze here."}
    codes = [client.post("/analyze", json=payload).status_code for _ in range(11)]
    assert codes[:10] == [200] * 10
    assert codes[10] == 429


def test_rate_limit_response_has_retry_after():
    payload = {"text": "another normal sentence here."}
    for _ in range(10):
        client.post("/analyze", json=payload)
    r = client.post("/analyze", json=payload)
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    assert r.json()["retry_after_sec"] > 0


# --- Spend cap (global) -----------------------------------------------------

def test_spend_cap_fires_503(monkeypatch):
    # Shrink the global cap to 2 units so a couple analyses exhaust it.
    monkeypatch.setattr(main, "spend_cap", DailySpendCap(daily_cap=2.0))
    payload = {"text": "sentence for spend cap test here."}
    r1 = client.post("/analyze", json=payload)   # cost 1 -> ok (spent 1)
    r2 = client.post("/analyze", json=payload)   # cost 1 -> ok (spent 2)
    r3 = client.post("/analyze", json=payload)   # cost 1 -> would exceed -> 503
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 503
    assert r3.json()["error"] == "service_budget_reached"


# ============================ spend-cap unit ===============================

class FakeClock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t
    def advance(self, s): self.t += s


def test_charge_until_cap():
    cap = DailySpendCap(daily_cap=5.0)
    assert cap.check_and_charge(3).allowed
    assert cap.check_and_charge(2).allowed
    d = cap.check_and_charge(1)
    assert not d.allowed and d.reason == "daily_cap_reached"


def test_window_rolls_after_24h():
    clk = FakeClock()
    cap = DailySpendCap(daily_cap=5.0, clock=clk)
    cap.check_and_charge(5)
    assert not cap.check_and_charge(1).allowed
    clk.advance(24 * 3600 + 1)                 # new window
    assert cap.check_and_charge(5).allowed


def test_refund_returns_budget():
    cap = DailySpendCap(daily_cap=5.0)
    cap.check_and_charge(4)
    cap.refund(4)
    assert cap.check_and_charge(5).allowed     # full budget restored


def test_refund_never_negative():
    cap = DailySpendCap(daily_cap=5.0)
    cap.check_and_charge(1)
    cap.refund(100)                            # over-refund
    st = cap.status()
    assert st.spent_today == 0.0


def test_negative_cost_rejected():
    cap = DailySpendCap(daily_cap=5.0)
    d = cap.check_and_charge(-10)              # attacker trying to gain budget
    assert not d.allowed and d.reason == "invalid_cost"


def test_invalid_cap_rejected():
    with pytest.raises(ValueError):
        DailySpendCap(daily_cap=0)
