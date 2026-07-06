"""
Calibration harness for the deterministic engine.

PURPOSE
  Tune the engine's WEIGHTS and metric thresholds against a corpus of REAL text
  YOU collect, not against hand-picked samples (which overfit). It:
    1. Scores every text in a labeled corpus.
    2. Reports how well each metric separates 'good' from 'bad' (discrimination).
    3. Flags metrics that are noisy, inverted, or redundant.
    4. Optionally searches for weights that best match your human labels.

WHY HUMAN LABELS ARE REQUIRED
  A score is only 'right' relative to human judgment. You must label each text.
  The harness measures whether the engine agrees with YOU — it cannot invent
  ground truth. Do not calibrate on synthetic/auto-generated labels; that just
  teaches the engine your generator's bias.

CORPUS FORMAT  (corpus.jsonl — one JSON object per line)
  {"id": "blog_01", "label": "good", "source": "real marketing blog", "text": "..."}
  {"id": "ai_07",   "label": "bad",  "source": "raw GPT output, untouched", "text": "..."}
  label must be "good" or "bad" (or a 1-5 int in the 'rating' field if you
  prefer graded labels — see --graded).

USAGE
  python3 calibration_harness.py corpus.jsonl
  python3 calibration_harness.py corpus.jsonl --search   # grid-search weights
  python3 calibration_harness.py corpus.jsonl --graded   # use 1-5 ratings

OUTPUT
  - per-metric mean score for good vs bad + separation (effect size)
  - current composite AUC-style separation
  - (with --search) a suggested WEIGHTS dict that maximizes separation,
    printed for you to review and paste in — never auto-applied.
"""

from __future__ import annotations

import argparse
import json
import statistics as stats
import sys
from itertools import product
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from services.deterministic_engine import analyze, WEIGHTS  # noqa: E402

METRIC_NAMES = list(WEIGHTS.keys())


def load_corpus(path: str, graded: bool) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                print(f"  ! skipping malformed line {i}", file=sys.stderr)
                continue
            if "text" not in obj:
                continue
            if graded:
                if "rating" not in obj:
                    continue
            else:
                if obj.get("label") not in ("good", "bad"):
                    continue
            rows.append(obj)
    return rows


def cohens_d(a: list[float], b: list[float]) -> float:
    """Standardized separation between two groups. |d|>0.8 = large effect."""
    if len(a) < 2 or len(b) < 2:
        return 0.0
    ma, mb = stats.mean(a), stats.mean(b)
    va, vb = stats.pvariance(a), stats.pvariance(b)
    pooled = ((va + vb) / 2) ** 0.5
    return (ma - mb) / pooled if pooled else 0.0


def score_corpus(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows:
        report = analyze(r["text"])
        rec = {"id": r.get("id"), "label": r.get("label"),
               "rating": r.get("rating"),
               "composite": report.composite_score}
        for m in METRIC_NAMES:
            rec[m] = report.metrics[m].score
        out.append(rec)
    return out


def report_discrimination(scored: list[dict], graded: bool) -> None:
    if graded:
        # Correlate each metric with the human rating (Spearman-ish via Pearson
        # on ranks would be ideal; use Pearson on raw for a simple signal).
        ratings = [s["rating"] for s in scored]
        print("\nMetric vs human rating (Pearson r; want strongly positive):")
        print(f"  {'metric':18} {'r':>7}")
        for m in METRIC_NAMES + ["composite"]:
            vals = [s[m] for s in scored]
            r = _pearson(vals, ratings)
            flag = "  <-- weak/inverted" if r < 0.2 else ""
            print(f"  {m:18} {r:7.3f}{flag}")
        return

    good = [s for s in scored if s["label"] == "good"]
    bad = [s for s in scored if s["label"] == "bad"]
    print(f"\nCorpus: {len(good)} good, {len(bad)} bad")
    print(f"\n{'metric':18} {'good_mean':>9} {'bad_mean':>9} {'cohen_d':>8}")
    for m in METRIC_NAMES + ["composite"]:
        gd = [s[m] for s in good]
        bd = [s[m] for s in bad]
        d = cohens_d(gd, bd)
        flag = ""
        if d < 0:
            flag = "  <-- INVERTED (bad scores higher!)"
        elif d < 0.3:
            flag = "  <-- weak separator"
        print(f"{m:18} {stats.mean(gd):9.1f} {stats.mean(bd):9.1f} {d:8.2f}{flag}")
    print("\nInterpretation: cohen_d > 0.8 strong, 0.3-0.8 moderate, "
          "<0.3 weak, <0 inverted (drop or fix the metric).")


def _pearson(x: list[float], y: list[float]) -> float:
    n = len(x)
    if n < 2:
        return 0.0
    mx, my = stats.mean(x), stats.mean(y)
    num = sum((a - mx) * (b - my) for a, b in zip(x, y))
    dx = sum((a - mx) ** 2 for a in x) ** 0.5
    dy = sum((b - my) ** 2 for b in y) ** 0.5
    return num / (dx * dy) if dx and dy else 0.0


def search_weights(scored: list[dict]) -> None:
    """Coarse grid search for weights that maximize good/bad composite
    separation. Prints a suggested WEIGHTS dict — does NOT auto-apply.
    Intentionally coarse; this guides judgment, it doesn't replace it."""
    good = [s for s in scored if s["label"] == "good"]
    bad = [s for s in scored if s["label"] == "bad"]
    if len(good) < 3 or len(bad) < 3:
        print("\n[search] need >=3 good and >=3 bad samples; skipping.")
        return

    grid = [0.0, 0.05, 0.1, 0.15, 0.2, 0.25]
    best_d, best_w = -999.0, None
    # Limit the search space: try emphasizing each metric in turn rather than
    # full cartesian product (which explodes).
    for emphasis in METRIC_NAMES:
        for w_emph in grid[1:]:
            remaining = (1.0 - w_emph) / (len(METRIC_NAMES) - 1)
            w = {m: (w_emph if m == emphasis else remaining) for m in METRIC_NAMES}
            gd = [sum(s[m] * w[m] for m in METRIC_NAMES) for s in good]
            bd = [sum(s[m] * w[m] for m in METRIC_NAMES) for s in bad]
            d = cohens_d(gd, bd)
            if d > best_d:
                best_d, best_w = d, w

    print(f"\n[search] best separation cohen_d={best_d:.2f} with weights:")
    print("WEIGHTS = {")
    for m, val in best_w.items():
        print(f'    "{m}": {round(val, 3)},')
    print("}")
    print("# Review before applying. Coarse search — sanity-check against your "
          "domain knowledge; do not paste blindly.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Calibrate the deterministic engine.")
    ap.add_argument("corpus", help="path to corpus.jsonl")
    ap.add_argument("--search", action="store_true", help="grid-search weights")
    ap.add_argument("--graded", action="store_true", help="use 1-5 ratings not good/bad")
    args = ap.parse_args()

    rows = load_corpus(args.corpus, args.graded)
    if len(rows) < 6:
        print(f"Loaded only {len(rows)} usable rows. Collect more real text "
              "(aim for >=15 good and >=15 bad) before trusting results.",
              file=sys.stderr)
    scored = score_corpus(rows)
    report_discrimination(scored, args.graded)
    if args.search and not args.graded:
        search_weights(scored)


if __name__ == "__main__":
    main()
