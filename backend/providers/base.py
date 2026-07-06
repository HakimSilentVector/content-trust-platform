"""
Thin AI-provider interface.

Deliberately minimal for the 14-day MVP: ONE method. We are NOT building a
multi-provider abstraction yet (that was flagged as premature). But isolating
the provider behind one seam means:
  - the engine never imports the OpenAI SDK directly,
  - the API key lives in exactly one place,
  - tests can inject a FakeProvider with zero network calls.

CRITICAL: the provider takes a SYSTEM string and a USER string SEPARATELY.
Callers must never fold user-submitted text into the system string. The
data/instruction boundary is enforced by this signature.
"""

from __future__ import annotations

import os
from typing import Protocol


class AIProvider(Protocol):
    def complete(self, *, system: str, user: str, max_tokens: int = 1200) -> str:
        """Return the model's raw text completion. Deterministic settings
        (temperature=0) are the provider's responsibility."""
        ...


class OpenAIProvider:
    """Real provider. temperature=0 for maximum determinism on a
    non-deterministic substrate. Key from env ONLY — never a parameter,
    never logged, never sent to the client."""

    def __init__(self, model: str = "gpt-4o-mini") -> None:
        self._model = model
        self._key = os.environ.get("OPENAI_API_KEY")
        if not self._key:
            raise RuntimeError("OPENAI_API_KEY not set in environment")

    def complete(self, *, system: str, user: str, max_tokens: int = 1200) -> str:
        # Imported lazily so tests that use FakeProvider need no SDK installed.
        from openai import OpenAI

        client = OpenAI(api_key=self._key)
        resp = client.chat.completions.create(
            model=self._model,
            temperature=0,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format={"type": "json_object"},  # force JSON, narrows injection surface
        )
        return resp.choices[0].message.content or ""
