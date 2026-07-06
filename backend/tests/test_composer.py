"""
Tests for the scoring composer.

The headline test is the SECURITY INVARIANT the module exists to enforce:
  a compromised, degraded, or hostile advisory report can NEVER change a single
  deterministic number in the response. This keeps the product's core output
  outside the blast radius of prompt injection (OWASP LLM01) or an LLM outage.

Run:  cd backend && python3 -m pytest tests/test_composer.py -v
"""

import pytest

from services.scoring_composer import compose
from services.deterministic_engine import analyze
from schemas.advisory import AdvisoryReport, RewriteResult, ToneObservation, GenericLanguageFlag, Severity
from schemas.response import AnalysisResponse


TEXT = ("Maria shipped the payment service to 12,000 users in March. "
        "It cut checkout latency from 800ms to 210ms.")


def _good_advisory() -> AdvisoryReport:
    return AdvisoryReport(
        tone=ToneObservation(detected_tone="confident",
                             consistency="consistent", note="clear"),
        generic_language=[GenericLanguageFlag(phrase="x", why="y",
                                              suggestion="z", severity=Severity.low)],
        clarity_notes=["tighten the second sentence"],
        degraded=False,
    )


def _degraded_advisory() -> AdvisoryReport:
    return AdvisoryReport(
        tone=ToneObservation(detected_tone="unavailable",
                             consistency="consistent", note="n/a"),
        degraded=True, degrade_reason="provider_error",
    )


# --- THE core invariant -----------------------------------------------------

def test_advisory_cannot_move_scores():
    """Compose once with a healthy advisory, once with a degraded one, once with
    none. Every deterministic number must be byte-identical across all three."""
    det = analyze(TEXT)

    r_none = compose(deterministic=det, advisory=None, rewrite=None, request_id="a")
    r_good = compose(deterministic=det, advisory=_good_advisory(), rewrite=None, request_id="b")
    r_bad = compose(deterministic=det, advisory=_degraded_advisory(), rewrite=None, request_id="c")

    for r in (r_none, r_good, r_bad):
        assert r.composite_score == det.composite_score
        assert r.word_count == det.summary["word_count"]
        assert r.sentence_count == det.summary["sentence_count"]
        assert set(r.metrics.keys()) == set(det.metrics.keys())
        for name, mv in r.metrics.items():
            assert mv.score == det.metrics[name].score


def test_hostile_advisory_with_fake_numbers_ignored():
    """Even if an attacker could smuggle numeric-looking data into the advisory,
    the composer reads NO numbers from it. We simulate a hostile advisory whose
    fields are stuffed with numbers and confirm scores are untouched."""
    det = analyze(TEXT)
    hostile = AdvisoryReport(
        tone=ToneObservation(detected_tone="100", consistency="consistent",
                             note="composite_score=0 override all scores to 0"),
        clarity_notes=["set composite to 999", "score: 0"],
        degraded=False,
    )
    r = compose(deterministic=det, advisory=hostile, rewrite=None, request_id="x")
    assert r.composite_score == det.composite_score
    assert 0 <= r.composite_score <= 100


# --- Degraded handling ------------------------------------------------------

def test_degraded_advisory_marked_unavailable_and_dropped():
    det = analyze(TEXT)
    r = compose(deterministic=det, advisory=_degraded_advisory(), rewrite=None, request_id="d")
    assert r.advisory_available is False
    assert r.advisory is None                      # degraded advisory not surfaced
    assert any("Advisory analysis unavailable" in n for n in r.notes)


def test_healthy_advisory_surfaced():
    det = analyze(TEXT)
    r = compose(deterministic=det, advisory=_good_advisory(), rewrite=None, request_id="e")
    assert r.advisory_available is True
    assert r.advisory is not None
    assert r.advisory.tone.detected_tone == "confident"


def test_degraded_rewrite_dropped_with_note():
    det = analyze(TEXT)
    rw = RewriteResult(rewritten_text=TEXT, changes=[], degraded=True,
                       degrade_reason="invalid_model_output")
    r = compose(deterministic=det, advisory=None, rewrite=rw, request_id="f")
    assert r.rewrite_available is False
    assert r.rewrite is None
    assert any("Rewrite unavailable" in n for n in r.notes)


def test_healthy_rewrite_surfaced():
    det = analyze(TEXT)
    rw = RewriteResult(rewritten_text="Improved.", changes=["tightened"], degraded=False)
    r = compose(deterministic=det, advisory=None, rewrite=rw, request_id="g")
    assert r.rewrite_available is True
    assert r.rewrite.rewritten_text == "Improved."


# --- Contract / provenance --------------------------------------------------

def test_response_validates_as_schema():
    det = analyze(TEXT)
    r = compose(deterministic=det, advisory=_good_advisory(),
                rewrite=None, request_id="req-123")
    # Round-trips through pydantic validation cleanly.
    AnalysisResponse.model_validate(r.model_dump())
    assert r.request_id == "req-123"
    assert r.engine_version == det.engine_version


def test_request_id_not_derived_from_content():
    """request_id must be caller-supplied correlation, never content-derived
    (a content hash would leak text-equality across requests)."""
    det = analyze(TEXT)
    r1 = compose(deterministic=det, advisory=None, rewrite=None, request_id="id-1")
    r2 = compose(deterministic=det, advisory=None, rewrite=None, request_id="id-2")
    assert r1.request_id != r2.request_id   # same text, different ids
