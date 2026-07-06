"""
Scoring composer.

Merges the deterministic report (authoritative numbers) and the advisory report
(qualitative, untrusted) into one AnalysisResponse.

SECURITY INVARIANT (the whole reason this module exists):
  compose() reads scores ONLY from the deterministic report. It never reads a
  number from, or lets any value be influenced by, the advisory report. If the
  advisory is degraded or absent, every number is unchanged and the response
  simply carries advisory_available=False. This is verified in
  tests/test_composer.py::test_advisory_cannot_move_scores.

PRIVACY:
  The composer receives already-computed reports. It does not see, store, or log
  the original text. request_id is a random correlation id, never derived from
  content.
"""

from __future__ import annotations

from schemas.response import AnalysisResponse, MetricView
from services.deterministic_engine import DeterministicReport
from schemas.advisory import AdvisoryReport, RewriteResult


def compose(
    *,
    deterministic: DeterministicReport,
    advisory: AdvisoryReport | None,
    rewrite: RewriteResult | None,
    request_id: str,
) -> AnalysisResponse:
    # Numbers: sourced EXCLUSIVELY from the deterministic report.
    metrics = {
        name: MetricView(score=m.score, detail=m.detail)
        for name, m in deterministic.metrics.items()
    }

    notes: list[str] = []

    # Advisory: attach only if present AND not degraded. A degraded advisory is
    # treated as absent for trust purposes — we do not surface half-broken
    # qualitative output as if it were reliable.
    advisory_ok = advisory is not None and not advisory.degraded
    if advisory is not None and advisory.degraded:
        notes.append(
            f"Advisory analysis unavailable ({advisory.degrade_reason}); "
            "scores are deterministic and unaffected."
        )

    rewrite_ok = rewrite is not None and not rewrite.degraded
    if rewrite is not None and rewrite.degraded:
        notes.append(
            f"Rewrite unavailable ({rewrite.degrade_reason}); original text "
            "returned unchanged."
        )

    return AnalysisResponse(
        engine_version=deterministic.engine_version,
        composite_score=deterministic.composite_score,
        metrics=metrics,
        word_count=deterministic.summary.get("word_count", 0),
        sentence_count=deterministic.summary.get("sentence_count", 0),
        advisory_available=advisory_ok,
        advisory=advisory if advisory_ok else None,
        rewrite_available=rewrite_ok,
        rewrite=rewrite if rewrite_ok else None,
        request_id=request_id,
        notes=notes,
    )
