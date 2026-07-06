"""
API application: turns the verified components into a running service.

REQUEST PIPELINE for POST /analyze (order matters — cheapest/safest rejections
first, paid work last):

    1. request_id assigned (correlation, not content-derived)
    2. input_guard.check_text ...... reject oversized/malformed at ~0 cost
    3. rate_limiter.check .......... per-client rate ceiling (429 if exceeded)
    4. spend_cap.check_and_charge .. GLOBAL daily budget (503 if exhausted)
    5. deterministic_engine.analyze  ALWAYS runs (free, reproducible)
    6. advisory_engine.analyze ..... LLM; degrades safely, never blocks scores
    7. advisory_engine.rewrite ..... only if requested
    8. scoring_composer.compose .... merge; deterministic numbers authoritative
    (refund spend on provider failure so real users aren't charged for outages)

PRIVACY
  Submitted text lives only for the duration of the request and is never
  persisted or logged. No submissions table exists. request_id correlates logs
  without revealing content.

DEPLOY NOTE
  The advisory/rewrite steps require OPENAI_API_KEY in the environment. If it is
  absent, the deterministic path still works and advisory degrades gracefully —
  so the service is useful even before the key is configured.
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from middleware.input_guard import check_text
from middleware.rate_limit import TokenBucketRateLimiter
from middleware.spend_cap import DailySpendCap, COST_ANALYZE, COST_REWRITE
from middleware.error_handler import new_request_id, unhandled_exception_handler
from services.deterministic_engine import analyze as det_analyze
from services.advisory_engine import AdvisoryEngine
from services.scoring_composer import compose
from schemas.advisory import AdvisoryReport, RewriteResult

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("api")

# --- environment / deploy config -------------------------------------------
# ENV controls prod hardening. Default "production" so an UNSET env is the SAFE
# (locked-down) state, not the permissive one. Fail-safe by default.
ENV = os.environ.get("ENV", "production").lower()
IS_PROD = ENV == "production"

# CORS allowlist: EXPLICIT origins only, never "*". A wildcard would let any
# website call this paid API from a victim's browser (denial-of-wallet /
# API8:2023). Set ALLOWED_ORIGINS as a comma-separated list of your frontend
# URLs, e.g. "https://app.threatlenssec.com,https://threatlens.vercel.app".
_origins_raw = os.environ.get("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = [o.strip() for o in _origins_raw.split(",") if o.strip()]
if not IS_PROD and not ALLOWED_ORIGINS:
    # Dev convenience ONLY: local frontend. Never applied in production.
    ALLOWED_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]

# In production, disable the interactive docs + OpenAPI schema. They aid
# reconnaissance of your endpoints/params (T1592) and aren't needed by end
# users. Re-enable deliberately if you want public API docs later.
app = FastAPI(
    title="Content Trust Platform API",
    version="0.1.0",
    docs_url=None if IS_PROD else "/docs",
    redoc_url=None if IS_PROD else "/redoc",
    openapi_url=None if IS_PROD else "/openapi.json",
)

from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,   # explicit allowlist
    allow_credentials=False,         # we use no cookies; keep False to avoid
                                     # the browser rejecting a wildcard+creds combo
    allow_methods=["POST", "GET"],   # only what the API actually serves
    allow_headers=["Content-Type"],
    max_age=600,
)

# --- shared, process-wide singletons ---------------------------------------
# NOTE: in-memory state => single-instance only. Swap for Redis-backed stores
# before horizontal scaling (tracked limitation, documented in each module).
rate_limiter = TokenBucketRateLimiter(capacity=10, refill_per_sec=0.2)
spend_cap = DailySpendCap(daily_cap=float(os.environ.get("DAILY_SPEND_CAP", "1000")))


def _build_advisory_engine() -> AdvisoryEngine | None:
    """Construct the advisory engine only if a provider key exists. Returns
    None otherwise so the deterministic path runs without an LLM."""
    if not os.environ.get("OPENAI_API_KEY"):
        return None
    from providers.base import OpenAIProvider
    return AdvisoryEngine(provider=OpenAIProvider())


advisory_engine = _build_advisory_engine()


# --- request/response models ------------------------------------------------

class AnalyzeRequest(BaseModel):
    text: str = Field(..., description="Text to analyze. Treated as data, never instructions.")
    include_rewrite: bool = Field(default=False, description="Also return an improved version.")


# --- middleware: attach a request_id to every request -----------------------

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request.state.request_id = new_request_id()
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


app.add_exception_handler(Exception, unhandled_exception_handler)


# --- client-key derivation --------------------------------------------------

def _client_key(request: Request) -> str:
    """Per-client key for rate limiting. Uses the client IP for the pre-auth
    MVP. NEVER derived from submitted content. Replace with an auth/session id
    once accounts exist. Trust X-Forwarded-For ONLY behind a trusted proxy that
    sets it (Render does); otherwise it is client-spoofable."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "anonymous"


# --- routes -----------------------------------------------------------------

@app.get("/health")
async def health():
    """Liveness probe. Deliberately minimal: exposes NO internal figures.

    Earlier this returned live spend numbers — that is reconnaissance data
    (an attacker could learn the cap and time a denial-of-wallet burst against
    the window reset). A health check should confirm the process is alive and
    nothing more. Detailed spend belongs on an authenticated admin route."""
    return {"status": "ok", "advisory_available": advisory_engine is not None}


@app.post("/analyze")
async def analyze_endpoint(req: AnalyzeRequest, request: Request):
    rid = request.state.request_id

    # 2. Input guard — cheapest rejection, before any expensive work.
    guard = check_text(req.text)
    if not guard.ok:
        return JSONResponse(status_code=400,
                            content={"error": "invalid_input",
                                     "reason": guard.reason, "request_id": rid})
    text = guard.cleaned

    # 3. Per-client rate limit.
    rl = rate_limiter.check(_client_key(request))
    if not rl.allowed:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(int(rl.retry_after_sec) + 1)},
            content={"error": "rate_limited",
                     "retry_after_sec": rl.retry_after_sec, "request_id": rid})

    # 4. Global spend cap (denial-of-wallet backstop). Charge up front for the
    #    work we are about to do; refund on provider failure.
    planned_cost = COST_ANALYZE + (COST_REWRITE if req.include_rewrite else 0.0)
    spend = spend_cap.check_and_charge(planned_cost)
    if not spend.allowed:
        return JSONResponse(status_code=503,
                            content={"error": "service_budget_reached",
                                     "reason": spend.reason, "request_id": rid})

    # 5. Deterministic engine — always runs, free, reproducible.
    det = det_analyze(text)

    # 6/7. Advisory + optional rewrite. Each degrades safely on its own.
    advisory: AdvisoryReport | None = None
    rewrite: RewriteResult | None = None
    provider_failed = False

    if advisory_engine is not None:
        advisory = advisory_engine.analyze(text)
        if advisory.degraded and advisory.degrade_reason == "provider_error":
            provider_failed = True
        if req.include_rewrite:
            rewrite = advisory_engine.rewrite(text)
            if rewrite.degraded and rewrite.degrade_reason == "provider_error":
                provider_failed = True

    # Refund budget if the paid provider never actually delivered value.
    if provider_failed:
        spend_cap.refund(planned_cost)

    # 8. Compose — deterministic numbers authoritative; advisory cannot move them.
    result = compose(deterministic=det, advisory=advisory,
                     rewrite=rewrite, request_id=rid)
    return JSONResponse(status_code=200, content=result.model_dump())
