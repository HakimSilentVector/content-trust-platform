"""
Safe error handling for the API.

THREAT ADDRESSED
  Verbose error handling is a classic leak (OWASP API8:2023 Security
  Misconfiguration; sensitive-data-in-logs). Two failure modes we prevent:
    1. Leaking submitted text (or secrets) into logs on an exception.
    2. Leaking stack traces / internal detail to the CLIENT, which aids
       reconnaissance (T1592 Gather Victim Host Information).

DESIGN
  - The client always receives a generic message + a correlation request_id.
  - Logs record the request_id, the exception TYPE, and a path — never the
    request body, never the exception's stringified message (which may embed
    user content or a provider payload).
  - This is the enforcement point for the no-content-in-logs privacy rule.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import Request
from fastapi.responses import JSONResponse

log = logging.getLogger("api.errors")


def new_request_id() -> str:
    """Random correlation id. NOT derived from content (a content hash would
    leak text-equality across requests)."""
    return uuid.uuid4().hex


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    rid = getattr(request.state, "request_id", None) or new_request_id()
    # Log TYPE + path + id only. Never str(exc) (may contain user/provider text).
    log.error("unhandled_exception id=%s path=%s type=%s",
              rid, request.url.path, type(exc).__name__)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error",
                 "message": "An unexpected error occurred.",
                 "request_id": rid},
    )
