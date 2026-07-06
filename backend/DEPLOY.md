# Deploy Runbook — Content Trust Platform API

Ordered, operational steps to take the API from repo to live URL on Render.
Follow top to bottom. Steps marked **[MANUAL — YOU]** cannot be automated and
are security-critical.

---

## 0. Pre-flight (before any deploy)

- [ ] All tests green locally: `cd backend && python3 -m pytest -q`
- [ ] No secrets tracked: `git grep -nE 'sk-[A-Za-z0-9]{20,}'` returns nothing
- [ ] `.env` is in `.gitignore` AND `.dockerignore` (it is)
- [ ] CI is passing on `main` (the workflow gates merges)

## 1. [MANUAL — YOU] Set the OpenAI account hard spend cap FIRST

Before the service is reachable, set the billing backstop. This is the ONE
control that survives a bug in your own code.

- OpenAI dashboard → Settings → Billing → Limits
- Set a **hard monthly limit** = the largest bill you could absorb without harm
- Set a lower **alert threshold** for early warning

Do this before step 3. A live endpoint without this is an uncapped liability.

## 2. Connect the repo to Render

- Render dashboard → New → Blueprint → connect your GitHub repo
- Render reads `render.yaml` and provisions the `content-trust-api` web service
- Do NOT deploy yet — set env vars first (next step)

## 3. [MANUAL — YOU] Set secret + origin env vars in Render

`render.yaml` declares these with `sync: false`, meaning you set their VALUES
in the dashboard so they never touch the repo:

- `OPENAI_API_KEY` = your key (secret; never commit, never log)
- `ALLOWED_ORIGINS` = your frontend origin(s), comma-separated, NO trailing
  slash, e.g. `https://app.threatlenssec.com`
  - Leave this UNSET only if you want to run deterministic-only with no browser
    frontend; an unset allowlist in production blocks all cross-origin calls
    (the safe default).

Already set by the blueprint (adjust if needed):
- `ENV=production`  (disables /docs, strict CORS, no dev fallback)
- `DAILY_SPEND_CAP=1000`  (global cost-unit ceiling; tune to real $)

## 4. Deploy

- Trigger the first deploy (Render does this automatically once env vars exist
  if `autoDeploy` is on, or click Deploy)
- Watch the build log for the Docker build + gunicorn boot

## 5. Verify the live service

```bash
API=https://<your-service>.onrender.com

# Liveness — expect {"status":"ok","advisory_available":true}
curl -s $API/health

# Docs disabled in prod — expect 404
curl -s -o /dev/null -w "%{http_code}\n" $API/docs

# Analyze — expect a composite_score and 7 metrics
curl -s -X POST $API/analyze -H "Content-Type: application/json" \
  -d '{"text":"Replace with a real paragraph to analyze."}'

# CORS: a disallowed origin must NOT get an allow-origin header back
curl -s -D - -o /dev/null -X POST $API/analyze \
  -H "Content-Type: application/json" -H "Origin: https://evil.example.com" \
  -d '{"text":"test sentence here."}' | grep -i access-control-allow-origin || echo "no allow header (correct)"
```

`advisory_available` should be `true` here (key is set), unlike local tests.

## 6. Post-deploy hardening checklist

- [ ] Confirm `/health` exposes NO spend figures (it shouldn't)
- [ ] Confirm error responses return generic messages + request_id, no stack traces
- [ ] Set a billing alert on the Render service too (compute cost, separate from OpenAI)
- [ ] Note the cold-start behavior on the starter plan; first request after idle is slow

---

## Known limitations to track (not blocking, but do not forget)

1. **Single-worker / single-instance state.** Rate limiter + spend cap are
   in-memory. `Dockerfile` runs `--workers 1` so the global spend cap stays
   correct. Scaling to more workers or instances multiplies the effective caps.
   **Before scaling: move both stores to Redis.**

2. **`X-Forwarded-For` trust.** Rate-limit keying trusts this header. Correct
   behind Render (which sets it). If ever exposed without a trusted proxy, it is
   client-spoofable and defeats per-client limiting.

3. **IP-based keying is evadable** by rotation. The global spend cap + OpenAI
   account cap are the layers that hold against distributed abuse.
