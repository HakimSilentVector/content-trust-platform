"""
Output contract for the LLM advisory engine.

WHY THIS IS A SECURITY CONTROL, NOT JUST VALIDATION:
The LLM is only ever allowed to return data that fits these schemas. If a prompt
injection succeeds, the model's output will almost always FAIL to parse as this
schema (it'll be a leaked system prompt, an apology, free-form text, etc.).
So schema validation is our last-line injection tripwire: malformed output =>
reject + log the EVENT (never the text) => return a safe degraded response.

Advisory output is intentionally NON-NUMERIC. Numbers come only from the
deterministic engine. The LLM gives qualitative observations a human can judge.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal
from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"


class GenericLanguageFlag(BaseModel):
    phrase: str = Field(..., max_length=200)
    why: str = Field(..., max_length=300)
    suggestion: str = Field(..., max_length=300)
    severity: Severity

    @field_validator("phrase", "why", "suggestion")
    @classmethod
    def no_control_chars(cls, v: str) -> str:
        # Reject smuggled control characters / null bytes in model output.
        if any(ord(c) < 9 for c in v):
            raise ValueError("control characters not allowed")
        return v.strip()


class ToneObservation(BaseModel):
    detected_tone: str = Field(..., max_length=80)
    consistency: Literal["consistent", "mostly_consistent", "inconsistent"]
    note: str = Field(..., max_length=400)


class AdvisoryReport(BaseModel):
    """The ONLY shape the advisory engine will return upward. Anything else
    is treated as a failed/blocked call."""
    tone: ToneObservation
    generic_language: list[GenericLanguageFlag] = Field(default_factory=list, max_length=15)
    clarity_notes: list[str] = Field(default_factory=list, max_length=10)
    # Provenance / safety fields set by the engine, not the model:
    degraded: bool = False           # True if we fell back due to a bad/blocked call
    degrade_reason: str | None = None

    @field_validator("clarity_notes")
    @classmethod
    def cap_note_length(cls, v: list[str]) -> list[str]:
        return [n.strip()[:400] for n in v]


class RewriteResult(BaseModel):
    rewritten_text: str = Field(..., max_length=20000)
    changes: list[str] = Field(default_factory=list, max_length=25)
    degraded: bool = False
    degrade_reason: str | None = None
