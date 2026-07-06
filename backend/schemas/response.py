"""
Final API response contract: the single shape the frontend binds to.

INVARIANT (enforced by the composer, verified by tests):
  Every numeric field originates from the DETERMINISTIC engine. The advisory
  layer contributes only qualitative text and can be entirely absent
  (advisory_available=False) without changing a single number. This keeps the
  product's core output outside the blast radius of a prompt-injection or an
  LLM outage.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from schemas.advisory import AdvisoryReport, RewriteResult


class MetricView(BaseModel):
    """One deterministic metric, flattened for the UI."""
    score: float
    detail: dict


class AnalysisResponse(BaseModel):
    # --- authoritative, deterministic ---
    engine_version: str
    composite_score: float = Field(..., ge=0, le=100)
    metrics: dict[str, MetricView]
    word_count: int
    sentence_count: int

    # --- advisory, may be degraded/absent ---
    advisory_available: bool
    advisory: AdvisoryReport | None = None

    # --- optional rewrite (only when requested) ---
    rewrite_available: bool = False
    rewrite: RewriteResult | None = None

    # --- provenance for auditability / trust ---
    request_id: str          # correlation id for logs (NOT the text)
    notes: list[str] = Field(default_factory=list)
