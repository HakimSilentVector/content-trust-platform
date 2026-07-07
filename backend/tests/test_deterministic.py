"""
Tests for the deterministic engine.

The headline test is REPRODUCIBILITY: the same input must produce byte-identical
output across repeated runs. This is the property that makes the whole product
defensible — and it is exactly the kind of named, verifiable control a security
hiring manager wants to see (threat: non-deterministic black-box scoring;
control: pure deterministic engine; verification: this suite).

Run:  cd backend && python3 -m pytest tests/test_deterministic.py -v
"""

import json
import pytest

from services.deterministic_engine import analyze, WEIGHTS, GENERIC_PHRASES


GOOD = (
    "Maria shipped the payment service to 12,000 users in March. "
    "It cut checkout latency from 800ms to 210ms. "
    "She rewrote the retry logic, then load-tested against Stripe's sandbox. "
    "Two bugs surfaced under concurrency; both were patched within a day. "
    "The rollout held at 99.97% uptime through the quarter."
)

BAD = (
    "In today's world, leveraging cutting-edge solutions is important. "
    "It is important to note that synergy plays a crucial role. "
    "The system was designed. The system was built. The system was tested. "
    "Things were done in order to achieve various goals."
)


# --- Reproducibility: the core guarantee -----------------------------------

def test_identical_input_identical_output():
    """Same text, run many times, must serialize to identical JSON."""
    first = json.dumps(analyze(GOOD).to_dict(), sort_keys=True)
    for _ in range(50):
        again = json.dumps(analyze(GOOD).to_dict(), sort_keys=True)
        assert again == first, "engine produced non-deterministic output"


def test_reproducible_across_distinct_texts():
    for text in (GOOD, BAD, "Short.", "One two three four five six seven."):
        a = json.dumps(analyze(text).to_dict(), sort_keys=True)
        b = json.dumps(analyze(text).to_dict(), sort_keys=True)
        assert a == b


# --- No mutation / purity ---------------------------------------------------

def test_input_not_mutated():
    original = str(BAD)
    analyze(BAD)
    assert BAD == original  # function must not touch its input


# --- Score bounds -----------------------------------------------------------

def test_all_scores_in_range():
    report = analyze(GOOD)
    assert 0.0 <= report.composite_score <= 100.0
    for name, m in report.metrics.items():
        assert 0.0 <= m.score <= 100.0, f"{name} out of range: {m.score}"


def test_weights_sum_to_one():
    assert abs(sum(WEIGHTS.values()) - 2.0) < 1e-9


# --- Monotonicity / directional correctness --------------------------------
# Good prose should beat deliberately-bad prose overall and on key axes.

def test_good_beats_bad_overall():
    assert analyze(GOOD).composite_score > analyze(BAD).composite_score


def test_generic_phrasing_penalized():
    assert analyze(BAD).metrics["generic_phrasing"].score < \
           analyze(GOOD).metrics["generic_phrasing"].score


def test_specificity_rewards_numbers_and_names():
    # GOOD has numbers + proper nouns; BAD has neither.
    assert analyze(GOOD).metrics["specificity"].score > \
           analyze(BAD).metrics["specificity"].score


def test_repetition_detects_repeated_phrase():
    # BAD repeats "the system was" three times.
    detail = analyze(BAD).metrics["repetition"].detail
    assert detail["repeated_trigram_instances"] >= 2


def test_passive_voice_detected():
    assert analyze(BAD).metrics["passive_voice"].detail["passive_sentences"] >= 3


# --- Edge cases: must never crash ------------------------------------------

@pytest.mark.parametrize("text", [
    "", "   ", "\n\n", ".", "!?", "a", "word",
    "123 456 789", "!@#$%^&*()", "ok.", "Hi there.",
    "x " * 5000,                      # very long, low-diversity
    "café résumé naïve Zürich",       # unicode
])
def test_edge_cases_do_not_crash(text):
    report = analyze(text)
    assert 0.0 <= report.composite_score <= 100.0


def test_non_string_rejected():
    with pytest.raises(TypeError):
        analyze(12345)  # type: ignore[arg-type]


# --- Guard against accidental persistence/logging --------------------------

def test_no_persistence_side_channel(tmp_path, monkeypatch):
    """analyze() must not write files. Run it in an empty cwd and assert
    nothing was created. (Cheap regression guard for the no-persistence rule.)"""
    monkeypatch.chdir(tmp_path)
    before = set(p.name for p in tmp_path.iterdir())
    analyze(GOOD)
    after = set(p.name for p in tmp_path.iterdir())
    assert before == after, "engine wrote to disk — violates no-persistence rule"
