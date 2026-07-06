# Content Trust Platform

A writing-quality analysis API that scores text on measurable, reproducible
metrics and layers optional AI observations on top — with the two kept
architecturally separate so the AI can never move the measured score.

This repository is built as much to demonstrate **security engineering** as to
be a working product. The security decisions are documented inline and verified
by an automated test suite (see [SECURITY.md](SECURITY.md) for the full threat
model).

---

## What it does

`POST /analyze` takes a block of text and returns:

- **Measured scores** (deterministic): readability, sentence variety, phrase
  repetition, lexical diversity, passive-voice ratio, specificity, and
  generic-phrase detection — composed into a 0–100 quality score. Same input
  always produces the same output.
- **Advisory observations** (AI, optional): tone, generic-language flags, and
  clarity notes, clearly labeled as AI-generated and unable to affect the
  measured score.
- **An improved rewrite** (AI, optional) with a before/after comparison.

The product never stores submitted text. Analysis happens in memory and the
text is discarded.

---

## Why it's built this way (the security story)

The interesting engineering here is the set of trust boundaries. Three examples:

**1. Deterministic scores are outside the AI's blast radius.**
An LLM is non-deterministic and injectable. If it produced the numeric scores,
a crafted input could manipulate them and the same text could score differently
on each run. Instead, every number comes from a pure-Python engine with no
network and no randomness; the AI layer contributes only qualitative text. A
prompt injection or an LLM outage degrades the advice, never the score.
*Verified by `test_composer.py`.*

**2. Prompt injection is deflected, not hoped away** (OWASP LLM01).
User text is the entire input to the AI layer, so injection is the primary
threat. User text is passed as a separate data block, never interpolated into
the model's instructions; forged delimiters are scrubbed; and every model
response must validate against a strict schema — output that doesn't (a leaked
prompt, an injected instruction's result) is rejected and the call degrades
safely. *Verified by `test_injection.py` against a corpus of real attack
strings.*

**3. Denial-of-wallet is defended in depth** (T1499 / OWASP API4:2023).
Every AI call costs money, so an attacker who can force calls can run up the
bill. Three independent layers: a per-client token-bucket rate limiter, a
global daily spend cap denominated in cost (with refund-on-failure so outages
don't penalize real users), and an account-level hard cap as the backstop.
*Verified by `test_middleware.py` and `test_api.py`.*

Full detail, including the controls that are NOT yet implemented and why, is in
[SECURITY.md](SECURITY.md).

---

## Architecture

```
Client (frontend/index.html)
   │  POST /analyze   (textContent-only rendering; no browser storage)
   ▼
FastAPI app (main.py)
   │  request pipeline — cheapest/safest rejections first, paid work last:
   │  1. input_guard    reject oversized/malformed  (~0 cost)
   │  2. rate_limit     per-client token bucket       (429)
   │  3. spend_cap      global daily budget            (503)
   │  4. deterministic_engine   ALWAYS runs (free, reproducible)
   │  5. advisory_engine        AI; degrades safely, never blocks scores
   │  6. scoring_composer       merge; deterministic numbers authoritative
   ▼
Response (schemas/response.py) — measured + advisory clearly separated
```

## Layout

```
backend/
  main.py                     FastAPI app + request pipeline
  services/
    deterministic_engine.py   pure-Python metrics (no LLM, no network)
    advisory_engine.py        LLM layer, injection-hardened, safe-degrading
    scoring_composer.py       merges tiers; enforces score authority
  providers/base.py           thin AI-provider seam (key from env only)
  prompts/templates.py        versioned system prompts (instructions only)
  middleware/
    input_guard.py            size/encoding/control-char validation
    rate_limit.py             per-client token bucket
    spend_cap.py              global daily cost ceiling + refund
    error_handler.py          generic errors; never logs request bodies
  schemas/                    pydantic contracts (advisory, response)
  tests/                      66 tests (see "Testing" below)
  calibration_harness.py      tune metric weights against a real corpus
  frontend/index.html         single-file client, wired to the API
  Dockerfile / render.yaml    containerized, deployable to Render
  DEPLOY.md                   ordered deploy runbook
  SECURITY.md                 threat model + control inventory
```

---

## Running locally

```bash
cd backend
pip install -r requirements.txt

# Deterministic-only (no AI): the service is fully useful with no key.
ENV=development uvicorn main:app --reload

# With AI advice + rewrite:
export OPENAI_API_KEY=sk-...           # never commit this
ENV=development uvicorn main:app --reload
```

Then open `frontend/index.html` and point its endpoint field at
`http://localhost:8000`.

## Testing

```bash
cd backend && python3 -m pytest -q     # 66 tests, ~4s, no network required
```

| File | Focus |
|---|---|
| `test_deterministic.py` | reproducibility (identical input → identical output), score bounds, edge cases |
| `test_injection.py` | prompt-injection deflection across four control layers |
| `test_composer.py` | the invariant that advisory data can't move a measured score |
| `test_middleware.py` | rate limiter (deterministic clock) + input guard |
| `test_api.py` | end-to-end pipeline, CORS allowlist, spend cap, error hygiene |

Tests run with **no API key and no network** — the AI path is exercised through
injected fakes, so the suite is deterministic and CI-safe.

## Deploying

See [DEPLOY.md](DEPLOY.md). Two steps are manual and security-critical: set the
OpenAI account spend cap, and set the CORS `ALLOWED_ORIGINS` to your frontend
URL.

---

## Known limitations (tracked, not hidden)

- Rate limiter and spend cap are in-memory → single-instance/single-worker only.
  Scaling horizontally multiplies the effective caps; move both to Redis first.
- Rate-limit keying trusts `X-Forwarded-For`, correct only behind a trusted
  proxy (Render sets it); exposed directly, it is spoofable.
- Metric weights are reasoned, not yet empirically calibrated — run
  `calibration_harness.py` against a labeled real-text corpus to tune them.

## Scope note

The measured score is a **writing-quality composite**, not a guarantee of
factual accuracy or authorship. It deliberately does not claim to detect
AI-generated text.
