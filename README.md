# Content Trust Platform

An LLM-powered writing-analysis API, built as a security-engineering artifact.
Deterministic scoring is kept outside the language model's blast radius; the AI
layer is advisory only and can never move a measured score. Every security
control is documented as threat -> control -> verification and proven by an
automated test suite.

**Live demo:** https://content-trust-api.onrender.com
**Security architecture:** [SECURITY.md](backend/SECURITY.md) ·
**Backend detail:** [backend/README.md](backend/README.md)

---

## What it does

`POST /analyze` scores text on seven reproducible writing-quality metrics
(readability, sentence variety, repetition, lexical diversity, passive voice,
specificity, generic-phrase detection) and layers optional AI observations —
tone, generic-language flags, an improved rewrite — clearly marked as advisory.
Submitted text is processed in memory and never stored.

## Security architecture

The engineering interest is in the trust boundaries. Three headline controls:

- **Deterministic scores outside the AI blast radius.** Numbers come from a
  pure-Python engine (no network, no randomness); the AI contributes only
  qualitative text. A prompt injection or model outage degrades the advice,
  never the score. *Verified by `test_composer.py`.*
- **Prompt-injection deflection (OWASP LLM01).** User text is passed as a
  delimited data block, never interpolated into instructions; forged delimiters
  are scrubbed; malformed model output fails schema validation and degrades
  safely. *Verified by `test_injection.py` against a real attack corpus.*
- **Layered denial-of-wallet defense (MITRE T1499 / OWASP API4:2023).**
  Per-client token-bucket rate limiter, global daily spend cap with
  refund-on-failure, and an account-level backstop. *Verified by
  `test_middleware.py` and `test_api.py`.*

Full threat model, framework mappings (MITRE ATT&CK, NIST CSF, OWASP), and a
tracked known-gaps table: [SECURITY.md](backend/SECURITY.md).

## Verification

93 tests pass across four environments (dev sandbox, local Windows, container,
GitHub Actions runners) and two Python versions (3.11, 3.12), with no network
and no API key required — the AI path is exercised through injected fakes.

The CI merge gate was **validated by controlled attack**: a deliberately failing
test was pushed via PR to confirm required checks block the merge. The exercise
surfaced an admin-bypass exemption in the branch-protection rule, which was
closed and re-verified (see closed PR #1). Implement -> test -> find gap ->
remediate -> re-test.

## Run locally

```bash
cd backend
pip install -r requirements.txt
ENV=development uvicorn main:app --reload   # deterministic path, no key needed
```

## Try the live API

```bash
curl -X POST https://content-trust-api.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"text":"The quarterly report shows revenue increased across all regions. Growth was strongest in the Pacific division, where new accounts were opened. Margins were compressed by rising costs. Leadership expects the trend to continue."}'
```

Returns `composite_score` plus the seven sub-metrics. The advisory layer is
disabled in the keyless public demo (`advisory_available: false`) — the
deterministic engine runs standalone, which is the point of the trust boundary.

## Roadmap

Runtime detection is the next maturity step: rate-limit and spend-cap events are
logged as structured metadata; shipping them to a SIEM and alerting on the
distributed-abuse signal (many 503s across many client keys, MITRE T1499) would
close the runtime-monitoring gap.

## Known limitations

Tracked openly in [SECURITY.md](backend/SECURITY.md): in-memory
rate-limiter/spend-cap are single-instance (Redis before horizontal scaling);
metric weights are reasoned, not yet empirically calibrated.

## Scope note

The score is a writing-quality composite, not a guarantee of factual accuracy
or authorship. It deliberately does not claim to detect AI-generated text.
