"""Validated LLM output contracts.

The model is asked for JSON matching these schemas (Groq strict structured outputs where supported), and
every response is re-validated here. Anything that does not validate is discarded.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

LLMStatus = Literal[
    "ok",
    "disabled",
    "not_configured",
    "skipped",
    "rate_limited",
    "timeout",
    "provider_error",
    "auth_error",
    "invalid_output",
]


class SignalCategory(StrEnum):
    URGENCY = "urgency"
    CREDENTIAL_REQUEST = "credential_request"
    PAYMENT_REQUEST = "payment_request"
    IMPERSONATION = "impersonation"
    REWARD_LURE = "reward_lure"
    JOB_SCAM = "job_scam"
    SECRECY = "secrecy"
    VERIFICATION_BYPASS = "verification_bypass"
    REMOTE_ACCESS = "remote_access"
    DOWNLOAD_INSTALL = "download_install"
    PERSONAL_INFO = "personal_info"
    PROMPT_INJECTION = "prompt_injection"
    LINK_LURE = "link_lure"
    OTHER = "other"


def _clip(value: Any, limit: int) -> Any:
    if isinstance(value, str):
        value = " ".join(value.split())
        return value[:limit]
    return value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LLMSignal(_Strict):
    category: SignalCategory
    signal: str
    explanation: str
    evidence: str

    @field_validator("signal", mode="before")
    @classmethod
    def _c1(cls, v: Any) -> Any:
        return _clip(v, 80)

    @field_validator("explanation", mode="before")
    @classmethod
    def _c2(cls, v: Any) -> Any:
        return _clip(v, 300)

    @field_validator("evidence", mode="before")
    @classmethod
    def _c3(cls, v: Any) -> Any:
        return _clip(v, 200)


class LLMAnalysis(_Strict):
    summary: str
    social_engineering_signals: list[LLMSignal]
    recommendations: list[str]
    limitations: list[str]

    @field_validator("summary", mode="before")
    @classmethod
    def _summary(cls, v: Any) -> Any:
        return _clip(v, 700)

    @field_validator("social_engineering_signals", mode="before")
    @classmethod
    def _signals(cls, v: Any) -> Any:
        return v[:8] if isinstance(v, list) else v

    @field_validator("recommendations", "limitations", mode="before")
    @classmethod
    def _lists(cls, v: Any) -> Any:
        if isinstance(v, list):
            return [_clip(item, 220) for item in v[:6] if isinstance(item, str) and item.strip()]
        return v


class IncidentSummary(_Strict):
    summary: str
    key_observations: list[str]
    next_steps: list[str]
    limitations: list[str]

    @field_validator("summary", mode="before")
    @classmethod
    def _summary(cls, v: Any) -> Any:
        return _clip(v, 900)

    @field_validator("key_observations", "next_steps", "limitations", mode="before")
    @classmethod
    def _lists(cls, v: Any) -> Any:
        if isinstance(v, list):
            return [_clip(item, 240) for item in v[:6] if isinstance(item, str) and item.strip()]
        return v


def _str_array() -> dict[str, Any]:
    return {"type": "array", "items": {"type": "string"}}


# Hand-written JSON Schemas for Groq strict mode: every property required, additionalProperties false.
ANALYSIS_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "social_engineering_signals": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "category": {"type": "string", "enum": [c.value for c in SignalCategory]},
                    "signal": {"type": "string"},
                    "explanation": {"type": "string"},
                    "evidence": {"type": "string"},
                },
                "required": ["category", "signal", "explanation", "evidence"],
                "additionalProperties": False,
            },
        },
        "recommendations": _str_array(),
        "limitations": _str_array(),
    },
    "required": ["summary", "social_engineering_signals", "recommendations", "limitations"],
    "additionalProperties": False,
}

INCIDENT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "key_observations": _str_array(),
        "next_steps": _str_array(),
        "limitations": _str_array(),
    },
    "required": ["summary", "key_observations", "next_steps", "limitations"],
    "additionalProperties": False,
}
