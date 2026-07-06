"""
Deterministic writing-quality engine.

DESIGN CONTRACT (do not break):
  - Pure function of input text. No LLM calls. No network. No randomness.
  - Same input -> identical output, on every run, on every machine.
  - This is the reproducible backbone the LLM advisory layer is composed on top of.
  - Submitted text is NEVER persisted or logged here. It is computed and discarded.

Every score is normalized to 0-100 (higher = better writing quality), with the
raw underlying measurement returned alongside so the UI can explain *why*.
"""

from __future__ import annotations

import re
import math
from dataclasses import dataclass, asdict, field
from typing import Any

import textstat

# textstat reads a global locale; pin it so output is identical everywhere.
textstat.set_lang("en")

# ----------------------------------------------------------------------------
# Tokenization — deliberately simple, regex-based, fully deterministic.
# (No nltk download step => no network, no version drift in tokenization.)
# ----------------------------------------------------------------------------

_SENTENCE_SPLIT = re.compile(r"[.!?]+(?:\s+|$)")
_WORD_RE = re.compile(r"[A-Za-z']+")

# Hedge / filler / generic phrases that flatten writing. Curated, not exhaustive;
# versioned intentionally so scoring changes are auditable.
GENERIC_PHRASES = (
    "in today's world", "in the world of", "at the end of the day",
    "it is important to note", "it's important to note", "it is worth noting",
    "needless to say", "in order to", "due to the fact that",
    "in conclusion", "when it comes to", "a wide range of", "a variety of",
    "plays a crucial role", "plays a vital role", "plays a key role",
    "in the realm of", "navigate the", "navigating the", "delve into",
    "in this day and age", "first and foremost", "last but not least",
    "the fact of the matter", "for all intents and purposes",
    "in the grand scheme of things", "leverage", "synergy",
    "cutting-edge", "game-changer", "game-changing", "seamless",
    "robust solution", "unlock the power", "harness the power",
    "take it to the next level", "think outside the box",
    "moving forward", "circle back", "low-hanging fruit",
    "best-in-class", "world-class", "state-of-the-art",
)


def _sentences(text: str) -> list[str]:
    parts = _SENTENCE_SPLIT.split(text.strip())
    return [s for s in (p.strip() for p in parts) if s]


def _words(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


def _clamp(x: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, x))


def _round(x: float, n: int = 1) -> float:
    # Deterministic, locale-independent rounding for stable output.
    return float(f"{x:.{n}f}")


# ----------------------------------------------------------------------------
# Individual metrics. Each returns (score_0_100, detail_dict).
# ----------------------------------------------------------------------------

def readability_metric(text: str, words: list[str]) -> tuple[float, dict[str, Any]]:
    """Flesch Reading Ease, remapped to a 0-100 quality score.

    Flesch is already 0-100 (higher = easier). We treat the 50-70 band
    ('plain English' / standard business prose) as the target and gently
    penalize text that is either painfully dense or oversimplified.
    """
    if len(words) < 5:
        return 0.0, {"flesch_reading_ease": None, "grade_level": None,
                     "note": "too short to assess"}

    flesch = textstat.flesch_reading_ease(text)
    grade = textstat.flesch_kincaid_grade(text)

    # Target band 50-70 -> full marks. Distance outside the band costs points.
    if 50 <= flesch <= 70:
        score = 100.0
    elif flesch < 50:
        score = _clamp(100 - (50 - flesch) * 1.2)   # too dense
    else:
        score = _clamp(100 - (flesch - 70) * 0.8)   # too simplistic

    return _round(score), {
        "flesch_reading_ease": _round(flesch),
        "grade_level": _round(grade),
        "target_band": "50-70 (plain professional English)",
    }


def sentence_variety_metric(text: str, sentences: list[str]) -> tuple[float, dict[str, Any]]:
    """Reward variation in sentence length. Monotone length == robotic.

    Uses coefficient of variation (std / mean) of words-per-sentence,
    mapped so CV ~0.5 (healthy human variation) scores high.
    """
    if len(sentences) < 2:
        return 0.0, {"sentence_count": len(sentences),
                     "note": "need >=2 sentences to assess variety"}

    lengths = [len(_words(s)) for s in sentences]
    n = len(lengths)
    mean = sum(lengths) / n
    if mean == 0:
        return 0.0, {"sentence_count": n, "note": "no words"}

    var = sum((l - mean) ** 2 for l in lengths) / n
    std = math.sqrt(var)
    cv = std / mean

    # CV 0 (all identical) -> 0 ; CV ~0.5+ -> 100, then plateau.
    score = _clamp(cv / 0.5 * 100)

    return _round(score), {
        "sentence_count": n,
        "avg_words_per_sentence": _round(mean),
        "shortest": min(lengths),
        "longest": max(lengths),
        "length_cv": _round(cv, 3),
    }


def repetition_metric(text: str, words: list[str]) -> tuple[float, dict[str, Any]]:
    """Penalize repeated 3-grams (phrase-level repetition).

    Score = 100 * (1 - repeated_trigram_ratio), so prose that never
    repeats a 3-word sequence scores 100.
    """
    if len(words) < 3:
        return 100.0, {"trigram_count": 0, "repeated_trigrams": 0,
                       "note": "too short to repeat"}

    trigrams = [tuple(words[i:i + 3]) for i in range(len(words) - 2)]
    total = len(trigrams)
    seen: dict[tuple, int] = {}
    for t in trigrams:
        seen[t] = seen.get(t, 0) + 1
    repeated = sum(c - 1 for c in seen.values() if c > 1)

    ratio = repeated / total if total else 0.0
    score = _clamp(100 * (1 - ratio * 3))  # weight repeats heavily

    top = sorted(((c, t) for t, c in seen.items() if c > 1), reverse=True)[:3]
    return _round(score), {
        "trigram_count": total,
        "repeated_trigram_instances": repeated,
        "most_repeated": [{"phrase": " ".join(t), "count": c} for c, t in top],
    }


def lexical_diversity_metric(text: str, words: list[str]) -> tuple[float, dict[str, Any]]:
    """Type-token ratio, length-corrected (root TTR) so long text isn't punished.

    rootTTR = unique_words / sqrt(total_words). Mapped to 0-100.
    """
    total = len(words)
    if total == 0:
        return 0.0, {"note": "no words"}
    unique = len(set(words))
    root_ttr = unique / math.sqrt(total)

    # Empirically, root TTR ~7+ is rich vocabulary; ~3 is repetitive.
    score = _clamp((root_ttr - 3) / (7 - 3) * 100)
    return _round(score), {
        "total_words": total,
        "unique_words": unique,
        "root_ttr": _round(root_ttr, 2),
    }


def passive_voice_metric(text: str, sentences: list[str]) -> tuple[float, dict[str, Any]]:
    """Heuristic passive-voice ratio. High passive == weaker, vaguer prose.

    Deterministic regex heuristic: 'be' verb + past participle (-ed / common
    irregulars) within a short window. Not linguistically perfect, but stable.
    """
    if not sentences:
        return 0.0, {"note": "no sentences"}

    be = r"(?:is|are|was|were|be|been|being|am)"
    irregular = (r"(?:done|made|seen|taken|given|written|known|held|found|"
                 r"shown|built|kept|sent|left|brought|told|paid|met)")
    pat = re.compile(rf"\b{be}\b\s+(?:\w+ly\s+)?(?:\w+ed|{irregular})\b", re.I)

    passive_hits = sum(1 for s in sentences if pat.search(s))
    ratio = passive_hits / len(sentences)
    score = _clamp(100 - ratio * 120)  # >~83% passive bottoms out

    return _round(score), {
        "sentences": len(sentences),
        "passive_sentences": passive_hits,
        "passive_ratio": _round(ratio, 3),
    }


def specificity_metric(text: str, words: list[str]) -> tuple[float, dict[str, Any]]:
    """Proxy for concrete vs. vague writing.

    Rewards numbers, proper nouns (mid-sentence capitalized words), and
    penalizes a high density of hedge/filler words. Fully deterministic.
    """
    if not words:
        return 0.0, {"note": "no words"}

    total = len(words)
    numbers = len(re.findall(r"\b\d[\d,.%$]*\b", text))

    # Proper nouns: capitalized words that are NOT sentence-initial.
    proper = 0
    for s in _sentences(text):
        toks = re.findall(r"\b[A-Za-z]+\b", s)
        for i, tok in enumerate(toks):
            if i > 0 and tok[0].isupper():
                proper += 1

    hedges = ("very", "really", "quite", "rather", "somewhat", "fairly",
              "things", "stuff", "various", "several", "many", "some",
              "generally", "usually", "often", "basically", "actually",
              "literally", "essentially", "kind", "sort")
    hedge_count = sum(1 for w in words if w in hedges)

    concrete_density = (numbers + proper) / total
    hedge_density = hedge_count / total

    raw = concrete_density * 250 - hedge_density * 150 + 40
    score = _clamp(raw)

    return _round(score), {
        "numbers": numbers,
        "proper_nouns_est": proper,
        "hedge_words": hedge_count,
        "concrete_density": _round(concrete_density, 3),
        "hedge_density": _round(hedge_density, 3),
    }


def generic_phrase_metric(text: str) -> tuple[float, dict[str, Any]]:
    """Flag clichés / filler phrases. Each hit costs points.

    This is the deterministic counterpart to the LLM's 'generic language'
    flagging — fast, free, reproducible, and explainable.
    """
    lower = text.lower()
    hits: list[dict[str, Any]] = []
    for phrase in GENERIC_PHRASES:
        c = lower.count(phrase)
        if c:
            hits.append({"phrase": phrase, "count": c})

    total_hits = sum(h["count"] for h in hits)
    words = len(_words(text)) or 1
    density = total_hits / words
    score = _clamp(100 - density * 1500)  # each cliché per ~ -15 pts at low counts

    hits.sort(key=lambda h: h["count"], reverse=True)
    return _round(score), {
        "generic_phrase_hits": total_hits,
        "phrases_found": hits[:10],
    }


# ----------------------------------------------------------------------------
# Composer
# ----------------------------------------------------------------------------

# Weights for the composite quality score. Tunable + versioned.
WEIGHTS = {
    "readability": 0.18,
    "sentence_variety": 0.16,
    "repetition": 0.14,
    "lexical_diversity": 0.14,
    "passive_voice": 0.12,
    "specificity": 0.16,
    "generic_phrasing": 0.10,
}

ENGINE_VERSION = "det-1.0.0"


@dataclass
class MetricResult:
    score: float
    detail: dict[str, Any]


@dataclass
class DeterministicReport:
    engine_version: str
    composite_score: float
    metrics: dict[str, MetricResult] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine_version": self.engine_version,
            "composite_score": self.composite_score,
            "metrics": {k: asdict(v) for k, v in self.metrics.items()},
            "summary": self.summary,
        }


def analyze(text: str) -> DeterministicReport:
    """Run all deterministic metrics and compose a weighted quality score.

    Pure function. No side effects. Text is not stored.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    sentences = _sentences(text)
    words = _words(text)

    r_read = MetricResult(*readability_metric(text, words))
    r_var = MetricResult(*sentence_variety_metric(text, sentences))
    r_rep = MetricResult(*repetition_metric(text, words))
    r_lex = MetricResult(*lexical_diversity_metric(text, words))
    r_pas = MetricResult(*passive_voice_metric(text, sentences))
    r_spec = MetricResult(*specificity_metric(text, words))
    r_gen = MetricResult(*generic_phrase_metric(text))

    metrics = {
        "readability": r_read,
        "sentence_variety": r_var,
        "repetition": r_rep,
        "lexical_diversity": r_lex,
        "passive_voice": r_pas,
        "specificity": r_spec,
        "generic_phrasing": r_gen,
    }

    composite = sum(metrics[k].score * w for k, w in WEIGHTS.items())

    return DeterministicReport(
        engine_version=ENGINE_VERSION,
        composite_score=_round(composite),
        metrics=metrics,
        summary={
            "word_count": len(words),
            "sentence_count": len(sentences),
            "weights": WEIGHTS,
        },
    )


if __name__ == "__main__":
    import json
    sample = (
        "In today's world, leveraging cutting-edge solutions is important. "
        "It is important to note that synergy plays a crucial role. "
        "The system was designed. The system was built. The system was tested. "
        "Things were done in order to achieve various goals."
    )
    print(json.dumps(analyze(sample).to_dict(), indent=2))
