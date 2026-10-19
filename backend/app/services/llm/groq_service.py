"""Groq LLM integration (server-side only).

- API key from GROQ_API_KEY; model from GROQ_MODEL (default openai/gpt-oss-20b, a Groq production model
  that supports strict json_schema structured outputs per console.groq.com/docs/structured-outputs).
- Strict structured outputs + Pydantic re-validation; invalid output is discarded.
- Timeouts, bounded SDK retries, a global per-minute request budget, and an overall deadline.
- Never logs prompts, responses or user content. Failures degrade to deterministic results.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, TypeVar

import groq
from pydantic import BaseModel, ValidationError

from app.core.config import Settings, get_settings
from app.core.logging import log_fields
from app.core.ratelimit import SlidingWindowLimiter
from app.services.llm import prompts
from app.services.llm.schemas import (
    ANALYSIS_JSON_SCHEMA,
    INCIDENT_JSON_SCHEMA,
    IncidentSummary,
    LLMAnalysis,
    LLMStatus,
)

logger = logging.getLogger("sentinel.llm")
T = TypeVar("T", bound=BaseModel)


@dataclass
class LLMOutcome[T: BaseModel]:
    status: LLMStatus
    data: T | None = None
    model: str | None = None
    latency_ms: int | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok" and self.data is not None


class GroqService:
    def __init__(self, settings: Settings | None = None, client: Any | None = None) -> None:
        self.settings = settings or get_settings()
        self._client = client
        self._budget = SlidingWindowLimiter()

    # -- lifecycle -------------------------------------------------------------------------------------
    def _get_client(self) -> Any:
        if self._client is None:
            assert self.settings.groq_api_key is not None
            kwargs: dict[str, Any] = {
                "api_key": self.settings.groq_api_key.get_secret_value(),
                "timeout": self.settings.groq_timeout_seconds,
                "max_retries": self.settings.groq_max_retries,
            }
            if self.settings.groq_base_url:
                kwargs["base_url"] = self.settings.groq_base_url
            self._client = groq.AsyncGroq(**kwargs)
        return self._client

    async def aclose(self) -> None:
        client, self._client = self._client, None
        if client is not None and hasattr(client, "close"):
            await client.close()

    def availability(self) -> LLMStatus | None:
        """Returns a non-ok status if calls cannot be attempted, else None."""
        if not self.settings.groq_enabled:
            return "disabled"
        if not self.settings.groq_configured:
            return "not_configured"
        return None

    # -- public operations -------------------------------------------------------------------------------
    async def analyze_message(self, text: str, content_type: str, rule_findings: list[str]) -> LLMOutcome[LLMAnalysis]:
        user = prompts.build_message_prompt(text, content_type, rule_findings)
        return await self._complete(
            prompts.MESSAGE_SYSTEM_PROMPT, user, "scam_analysis", ANALYSIS_JSON_SCHEMA, LLMAnalysis, "message"
        )

    async def explain_url(self, url_without_query: str, features: list[dict[str, str]]) -> LLMOutcome[LLMAnalysis]:
        user = prompts.build_url_prompt(url_without_query, features)
        return await self._complete(
            prompts.URL_SYSTEM_PROMPT, user, "url_explanation", ANALYSIS_JSON_SCHEMA, LLMAnalysis, "url"
        )

    async def summarize_incident(self, incident: dict[str, Any]) -> LLMOutcome[IncidentSummary]:
        user = prompts.build_incident_prompt(incident)
        return await self._complete(
            prompts.INCIDENT_SYSTEM_PROMPT, user, "incident_summary", INCIDENT_JSON_SCHEMA, IncidentSummary, "incident"
        )

    # -- core ------------------------------------------------------------------------------------------
    async def _complete(
        self, system: str, user: str, schema_name: str, json_schema: dict[str, Any], model_cls: type[T], operation: str
    ) -> LLMOutcome[T]:
        unavailable = self.availability()
        if unavailable:
            return LLMOutcome(status=unavailable)

        allowed, _ = await self._budget.hit("groq:global", self.settings.groq_requests_per_minute)
        if not allowed:
            self._log(operation, "rate_limited", None)
            return LLMOutcome(status="rate_limited", model=self.settings.groq_model)

        model = self.settings.groq_model
        started = time.perf_counter()
        # Overall deadline covers SDK retries so a user never waits indefinitely.
        deadline = self.settings.groq_timeout_seconds * (self.settings.groq_max_retries + 1) + 2
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        strict_format = {
            "type": "json_schema",
            "json_schema": {"name": schema_name, "strict": True, "schema": json_schema},
        }
        # Fallback when constrained decoding fails (Groq 400 `json_validate_failed`, observed intermittently):
        # one retry in JSON-object mode with the schema stated in the prompt. Output is still Pydantic-validated.
        fallback_messages = [
            {
                "role": "system",
                "content": f"{system}\n\nReturn ONLY a JSON object matching this JSON Schema:\n"
                f"{json.dumps(json_schema)}",
            },
            {"role": "user", "content": user},
        ]
        attempts: list[tuple[list[dict[str, str]], dict[str, Any]]] = [
            (messages, strict_format),
            (fallback_messages, {"type": "json_object"}),
        ]
        response: Any = None
        for index, (msgs, response_format) in enumerate(attempts):
            try:
                response = await asyncio.wait_for(
                    self._get_client().chat.completions.create(
                        model=model,
                        messages=msgs,
                        response_format=response_format,
                        temperature=0.2,
                        max_completion_tokens=self.settings.groq_max_completion_tokens,
                        reasoning_effort=self.settings.groq_reasoning_effort,
                        include_reasoning=False,
                    ),
                    timeout=deadline,
                )
                break
            except (TimeoutError, groq.APITimeoutError):
                return self._fail(operation, "timeout", started)
            except groq.RateLimitError:
                return self._fail(operation, "rate_limited", started, "rate_limit_exceeded")
            except (groq.AuthenticationError, groq.PermissionDeniedError):
                return self._fail(operation, "auth_error", started)
            except groq.APIStatusError as exc:
                code = _error_code(exc)
                if code == "json_validate_failed":
                    if index + 1 < len(attempts):
                        self._log(operation, "retry_json_object", None, code)
                        continue
                    return self._fail(operation, "invalid_output", started, code)
                return self._fail(operation, "provider_error", started, code)
            except (groq.APIConnectionError, groq.APIError):
                return self._fail(operation, "provider_error", started)

        latency = int((time.perf_counter() - started) * 1000)
        try:
            choice = response.choices[0]
            content = choice.message.content or ""
            if len(content) > 20_000:
                raise ValueError("response too large")
            data = model_cls.model_validate(json.loads(content))
        except (IndexError, AttributeError, ValueError, ValidationError, json.JSONDecodeError):
            self._log(operation, "invalid_output", latency)
            return LLMOutcome(status="invalid_output", model=model, latency_ms=latency)

        self._log(operation, "ok", latency)
        return LLMOutcome(status="ok", data=data, model=model, latency_ms=latency)

    def _fail(self, operation: str, status: LLMStatus, started: float, code: str | None = None) -> LLMOutcome[Any]:
        latency = int((time.perf_counter() - started) * 1000)
        self._log(operation, status, latency, code)
        return LLMOutcome(status=status, model=self.settings.groq_model, latency_ms=latency)

    def _log(self, operation: str, status: str, latency: int | None, provider_code: str | None = None) -> None:
        # Metadata only: never the prompt, the user content, or the response body.
        log_fields(
            logger,
            logging.INFO if status == "ok" else logging.WARNING,
            "llm_call",
            operation=operation,
            status=status,
            latency_ms=latency,
            model=self.settings.groq_model,
            provider_code=provider_code,
        )


def _error_code(exc: groq.APIStatusError) -> str | None:
    """Extracts the provider's machine-readable error code (never the message, which may echo content)."""
    body = exc.body if isinstance(exc.body, dict) else {}
    error = body.get("error", body)
    code = error.get("code") if isinstance(error, dict) else None
    return str(code)[:64] if code else None


_service: GroqService | None = None


def get_groq_service() -> GroqService:
    global _service
    if _service is None:
        _service = GroqService()
    return _service


def set_groq_service(service: GroqService | None) -> None:
    global _service
    _service = service
