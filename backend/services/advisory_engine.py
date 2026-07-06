"""
LLM advisory engine.

Produces QUALITATIVE, non-numeric observations (tone, generic-language flags,
clarity notes) and an optional rewrite. Numbers come only from the deterministic
engine; this layer is advisory by design.

SECURITY MODEL (OWASP LLM01 — Prompt Injection):
  Layer 1  Role separation .. instructions live in the system message; user
                              text is passed as the separate user message.
  Layer 2  Delimiting ....... user text is wrapped in explicit markers and the
                              system prompt tells the model to treat it as data.
  Layer 3  Output schema .... the model MUST return JSON matching schemas/advisory.
                              Anything else (a leaked prompt, an apology, prose)
                              fails validation -> we DEGRADE and log the EVENT.
  Layer 4  Pre-flight scrub .. we strip the model's own marker tokens out of
                              user text so a user can't forge the data boundary.

PRIVACY:
  Submitted text is processed in memory and discarded. NOTHING in this module
  writes user text to disk or to logs. Logs record metadata only (lengths,
  outcome, reason) — never content.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from pydantic import ValidationError

from providers.base import AIProvider
from prompts.templates import (
    ADVISORY_SYSTEM_V1, REWRITE_SYSTEM_V1,
    USER_START, USER_END,
    ADVISORY_PROMPT_VERSION, REWRITE_PROMPT_VERSION,
)
from schemas.advisory import AdvisoryReport, RewriteResult, ToneObservation

# Logger that, by contract, only ever receives metadata.
log = logging.getLogger("advisory_engine")

MAX_INPUT_CHARS = 12000  # hard cap; also enforced upstream by input_guard middleware


@dataclass
class AdvisoryEngine:
    provider: AIProvider

    # -- internal helpers ----------------------------------------------------

    @staticmethod
    def _wrap_user_text(text: str) -> str:
        """Wrap user text in data markers AFTER neutralizing any attempt to
        forge those markers. This stops a user pasting our own delimiter to
        'close' the data block early and inject instructions."""
        scrubbed = text.replace(USER_START, "").replace(USER_END, "")
        return f"{USER_START}\n{scrubbed}\n{USER_END}"

    @staticmethod
    def _parse_json(raw: str) -> dict:
        """Parse model output to a dict. Tolerates accidental code fences but
        nothing more exotic; anything unparseable raises (-> degrade)."""
        s = raw.strip()
        if s.startswith("```"):
            # strip ```json ... ``` fence if the model added one
            s = s.split("```", 2)[1] if s.count("```") >= 2 else s
            s = s[4:] if s.lower().startswith("json") else s
            s = s.strip().rstrip("`").strip()
        return json.loads(s)

    # -- public API ----------------------------------------------------------

    def analyze(self, text: str) -> AdvisoryReport:
        """Qualitative advisory analysis. Never raises on bad model output —
        returns a degraded report instead so the API stays up."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        text = text[:MAX_INPUT_CHARS]
        if len(text.strip()) < 3:
            return AdvisoryReport(
                tone=ToneObservation(detected_tone="n/a",
                                     consistency="consistent",
                                     note="Text too short to analyze."),
                degraded=False,
            )

        user_msg = self._wrap_user_text(text)
        try:
            raw = self.provider.complete(system=ADVISORY_SYSTEM_V1, user=user_msg)
            data = self._parse_json(raw)
            report = AdvisoryReport.model_validate(data)
            log.info("advisory ok prompt=%s in_chars=%d flags=%d",
                     ADVISORY_PROMPT_VERSION, len(text), len(report.generic_language))
            return report
        except (json.JSONDecodeError, ValidationError) as e:
            # Most likely a malformed response OR a deflected injection attempt.
            log.warning("advisory degraded prompt=%s reason=%s",
                        ADVISORY_PROMPT_VERSION, type(e).__name__)
            return self._degraded_advisory("invalid_model_output")
        except Exception as e:  # provider/network error
            log.error("advisory provider_error reason=%s", type(e).__name__)
            return self._degraded_advisory("provider_error")

    def rewrite(self, text: str) -> RewriteResult:
        """Optional improved version. Same hardening + degrade contract."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        text = text[:MAX_INPUT_CHARS]
        if len(text.strip()) < 3:
            return RewriteResult(rewritten_text=text, changes=[], degraded=False)

        user_msg = self._wrap_user_text(text)
        try:
            raw = self.provider.complete(system=REWRITE_SYSTEM_V1, user=user_msg,
                                         max_tokens=2000)
            data = self._parse_json(raw)
            result = RewriteResult.model_validate(data)
            log.info("rewrite ok prompt=%s in_chars=%d changes=%d",
                     REWRITE_PROMPT_VERSION, len(text), len(result.changes))
            return result
        except (json.JSONDecodeError, ValidationError) as e:
            log.warning("rewrite degraded prompt=%s reason=%s",
                        REWRITE_PROMPT_VERSION, type(e).__name__)
            # Safe degrade: return the ORIGINAL text unchanged. Never return
            # unvalidated model output to the user.
            return RewriteResult(rewritten_text=text, changes=[],
                                 degraded=True, degrade_reason="invalid_model_output")
        except Exception as e:
            log.error("rewrite provider_error reason=%s", type(e).__name__)
            return RewriteResult(rewritten_text=text, changes=[],
                                 degraded=True, degrade_reason="provider_error")

    # -- degrade helpers -----------------------------------------------------

    @staticmethod
    def _degraded_advisory(reason: str) -> AdvisoryReport:
        return AdvisoryReport(
            tone=ToneObservation(detected_tone="unavailable",
                                 consistency="consistent",
                                 note="Advisory analysis is temporarily "
                                      "unavailable; deterministic scores are "
                                      "unaffected."),
            generic_language=[],
            clarity_notes=[],
            degraded=True,
            degrade_reason=reason,
        )
