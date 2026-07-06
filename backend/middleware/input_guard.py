"""
Input guard.

FIRST line of defense on the /analyze endpoint. Runs BEFORE any LLM call so
malformed or oversized input is rejected at near-zero cost. Pure functions here;
FastAPI wiring is a thin adapter (see middleware/fastapi_adapters.py).

THREATS ADDRESSED
  - Oversized payloads -> memory pressure + inflated LLM token cost
    (OWASP LLM04 Unbounded Consumption).
  - Non-string / wrong-type bodies -> downstream type errors, potential DoS.
  - Control-character / null-byte smuggling -> log poisoning, parser abuse.
  - Empty/whitespace -> wasted LLM call for no value.

DESIGN
  Deterministic, side-effect-free validation returning a typed result. It does
  NOT log the text; on rejection it reports a reason code only.
"""

from __future__ import annotations

from dataclasses import dataclass

# Hard cap. Chosen to bound worst-case LLM token spend per request.
# 12k chars ~ 3k tokens input; keep in sync with advisory_engine.MAX_INPUT_CHARS.
MAX_CHARS = 12000
MIN_CHARS = 1


@dataclass(frozen=True)
class GuardResult:
    ok: bool
    reason: str | None = None      # machine code, safe to log
    cleaned: str | None = None     # normalized text when ok


def _has_disallowed_control_chars(text: str) -> bool:
    # Allow tab(9), LF(10), CR(13); reject other C0 controls and null.
    return any((ord(c) < 32 and c not in "\t\n\r") for c in text)


def check_text(body: object) -> GuardResult:
    """Validate a submitted-text payload. Returns GuardResult; never raises on
    bad user input (raising is for programmer error only)."""
    if not isinstance(body, str):
        return GuardResult(ok=False, reason="type_not_string")

    # Length check on the RAW string first (cheapest rejection).
    if len(body) > MAX_CHARS:
        return GuardResult(ok=False, reason="too_long")

    if _has_disallowed_control_chars(body):
        return GuardResult(ok=False, reason="control_chars")

    stripped = body.strip()
    if len(stripped) < MIN_CHARS:
        return GuardResult(ok=False, reason="empty")

    # Normalize: collapse nothing (preserve author's structure) but return the
    # length-capped original as the canonical cleaned value.
    return GuardResult(ok=True, cleaned=body)
