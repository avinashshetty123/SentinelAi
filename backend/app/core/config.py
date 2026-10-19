"""Application configuration loaded from environment variables (and an optional .env file).

All secrets are read server-side only. Nothing in this module is ever sent to the browser.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]

RiskLevelName = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BACKEND_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application ---
    app_name: str = "SentinelAI"
    app_version: str = "1.0.0"
    app_env: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"

    # --- Database ---
    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    database_echo: bool = False
    database_pool_size: int = Field(default=5, ge=1, le=50)

    # --- Groq LLM ---
    groq_api_key: SecretStr | None = None
    groq_model: str = "openai/gpt-oss-20b"
    groq_enabled: bool = True
    groq_base_url: str | None = None
    groq_timeout_seconds: float = Field(default=12.0, gt=0, le=60)
    groq_max_retries: int = Field(default=1, ge=0, le=3)
    groq_max_input_chars: int = Field(default=4000, ge=200, le=20000)
    groq_max_completion_tokens: int = Field(default=1500, ge=200, le=8000)
    groq_reasoning_effort: Literal["low", "medium", "high"] = "low"
    groq_requests_per_minute: int = Field(default=20, ge=1, le=1000)

    # --- HTTP / security ---
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    cors_origin_regex: str | None = None
    trust_proxy_headers: bool = False
    max_request_bytes: int = Field(default=65_536, ge=1024, le=1_048_576)
    max_message_chars: int = Field(default=10_000, ge=100, le=50_000)
    max_url_chars: int = Field(default=2048, ge=64, le=8192)

    # Authentication. "open" = single-operator demo with no credentials (refused in production unless
    # explicitly allowed). "token" = every non-health endpoint requires `Authorization: Bearer <token>`.
    auth_mode: Literal["open", "token"] = "open"
    admin_api_token: SecretStr | None = None
    allow_open_mode_in_production: bool = False

    # --- Rate limiting (in-process; suitable for a single instance) ---
    rate_limit_enabled: bool = True
    rate_limit_scans_per_minute: int = Field(default=30, ge=1)
    rate_limit_writes_per_minute: int = Field(default=60, ge=1)
    rate_limit_reads_per_minute: int = Field(default=300, ge=1)

    # --- Privacy & retention ---
    store_finding_excerpts: bool = False
    store_ai_summaries: bool = False
    scan_retention_days: int = Field(default=30, ge=1, le=3650)
    event_history_max: int = Field(default=5000, ge=100)

    # --- Detection / scoring ---
    risk_threshold_medium: int = Field(default=25, ge=1, le=98)
    risk_threshold_high: int = Field(default=50, ge=2, le=99)
    risk_threshold_critical: int = Field(default=75, ge=3, le=100)
    event_min_level: RiskLevelName = "HIGH"
    auto_incident_min_level: RiskLevelName | Literal["NONE"] = "CRITICAL"
    classifier_enabled: bool = True
    classifier_path: Path = BACKEND_ROOT / "ml" / "artifacts" / "sms_spam_tfidf_lr.json"

    # --- Demo ---
    demo_mode_enabled: bool = True
    demo_step_delay_seconds: float = Field(default=1.2, ge=0, le=10)
    demo_simulator_max_seconds: int = Field(default=300, ge=10, le=3600)

    @field_validator("database_url")
    @classmethod
    def _normalize_database_url(cls, value: str) -> str:
        # Render/Heroku style URLs use postgres:// or postgresql://; SQLAlchemy needs an explicit driver.
        if value.startswith("postgres://"):
            value = "postgresql://" + value[len("postgres://") :]
        for prefix in ("postgresql://", "postgresql+psycopg://", "postgresql+psycopg2://"):
            if value.startswith(prefix):
                value = "postgresql+asyncpg://" + value[len(prefix) :]
        if value.startswith("postgresql+asyncpg://"):
            # asyncpg uses `ssl=` rather than libpq's `sslmode=` query parameter.
            value = re.sub(r"([?&])sslmode=", r"\1ssl=", value)
        return value

    @field_validator("groq_api_key", "admin_api_token", mode="before")
    @classmethod
    def _empty_secret_is_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def _validate_combinations(self) -> Settings:
        if not (self.risk_threshold_medium < self.risk_threshold_high < self.risk_threshold_critical):
            raise ValueError("Risk thresholds must satisfy medium < high < critical")
        if self.auth_mode == "token":
            token = self.admin_api_token.get_secret_value() if self.admin_api_token else ""
            if len(token) < 24:
                raise ValueError("AUTH_MODE=token requires ADMIN_API_TOKEN of at least 24 characters")
        if self.app_env == "production" and self.auth_mode == "open" and not self.allow_open_mode_in_production:
            raise ValueError(
                "Refusing to start: AUTH_MODE=open in production. Set AUTH_MODE=token with ADMIN_API_TOKEN, "
                "or explicitly acknowledge a public demo with ALLOW_OPEN_MODE_IN_PRODUCTION=true."
            )
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip().rstrip("/") for o in self.cors_origins.split(",") if o.strip()]

    @property
    def groq_configured(self) -> bool:
        return bool(self.groq_api_key and self.groq_api_key.get_secret_value().strip())

    @property
    def groq_active(self) -> bool:
        return self.groq_enabled and self.groq_configured

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()
