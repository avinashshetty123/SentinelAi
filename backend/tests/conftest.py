"""Test fixtures.

Tests run against a temporary SQLite file by default (fast, no services needed). Set TEST_DATABASE_URL to a
PostgreSQL URL to run the same suite against PostgreSQL (CI does this).
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

_TMP = Path(tempfile.mkdtemp(prefix="sentinel-tests-"))
TEST_ENV = {
    "APP_ENV": "test",
    "DATABASE_URL": os.environ.get("TEST_DATABASE_URL", f"sqlite+aiosqlite:///{(_TMP / 'test.db').as_posix()}"),
    "GROQ_API_KEY": "",
    "GROQ_ENABLED": "false",
    "AUTH_MODE": "open",
    "ADMIN_API_TOKEN": "",
    "RATE_LIMIT_ENABLED": "false",
    "DEMO_MODE_ENABLED": "true",
    "DEMO_STEP_DELAY_SECONDS": "0",
    "STORE_FINDING_EXCERPTS": "false",
    "STORE_AI_SUMMARIES": "false",
    "CORS_ORIGINS": "http://localhost:3000",
    "AUTO_INCIDENT_MIN_LEVEL": "CRITICAL",
    "LOG_LEVEL": "WARNING",
}
os.environ.update(TEST_ENV)

import httpx  # noqa: E402
import pytest  # noqa: E402
from sqlalchemy import delete  # noqa: E402

import app.models  # noqa: E402,F401
from app.core.config import get_settings  # noqa: E402
from app.core.ratelimit import limiter, set_rate_limit_hook  # noqa: E402
from app.database.base import Base  # noqa: E402
from app.database.session import get_engine, get_sessionmaker, init_engine  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402
from app.services.detection.classifier import load_classifier  # noqa: E402
from app.services.events.service import on_rate_limited  # noqa: E402
from app.services.llm.groq_service import LLMOutcome, set_groq_service  # noqa: E402
from app.services.llm.schemas import LLMAnalysis  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
async def _database() -> AsyncIterator[None]:
    get_settings.cache_clear()
    init_engine()
    load_classifier(get_settings().classifier_path)
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest.fixture(autouse=True)
async def _clean_state() -> AsyncIterator[None]:
    limiter.reset()
    set_rate_limit_hook(on_rate_limited)  # normally registered by the app lifespan
    set_groq_service(None)
    yield
    set_groq_service(None)
    async with get_sessionmaker()() as session:
        for table in reversed(Base.metadata.sorted_tables):
            await session.execute(delete(table))
        await session.commit()


@pytest.fixture
def settings_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """Override settings for one test: settings_env(AUTH_MODE="token", ...)."""

    def apply(**values: str) -> None:
        for key, value in values.items():
            monkeypatch.setenv(key, value)
        get_settings.cache_clear()

    yield apply
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_settings_cache() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=fastapi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
async def session() -> AsyncIterator[Any]:
    async with get_sessionmaker()() as s:
        yield s


class FakeGroqService:
    """Stands in for GroqService in pipeline tests; records what it was sent."""

    def __init__(self, analysis: dict[str, Any] | None = None, status: str = "ok") -> None:
        self.analysis = analysis
        self.status = status
        self.calls: list[dict[str, Any]] = []

    def availability(self) -> None:
        return None

    async def analyze_message(self, text: str, content_type: str, rule_findings: list[str]) -> LLMOutcome[Any]:
        self.calls.append({"op": "message", "text": text, "content_type": content_type})
        return self._outcome()

    async def explain_url(self, url: str, features: list[dict[str, str]]) -> LLMOutcome[Any]:
        self.calls.append({"op": "url", "url": url, "features": features})
        return self._outcome()

    async def summarize_incident(self, incident: dict[str, object]) -> LLMOutcome[Any]:
        from app.services.llm.schemas import IncidentSummary

        self.calls.append({"op": "incident", "incident": incident})
        if self.status != "ok":
            return LLMOutcome(status=self.status, model="fake-model")  # type: ignore[arg-type]
        return LLMOutcome(status="ok", model="fake-model", latency_ms=5, data=IncidentSummary(
            summary="Synthetic incident summary.", key_observations=["Observation"], next_steps=["Step"],
            limitations=["Limitation"]))

    async def aclose(self) -> None:
        return None

    def _outcome(self) -> LLMOutcome[Any]:
        if self.status != "ok" or self.analysis is None:
            return LLMOutcome(status=self.status, model="fake-model", latency_ms=5)  # type: ignore[arg-type]
        return LLMOutcome(status="ok", model="fake-model", latency_ms=5,
                          data=LLMAnalysis.model_validate(self.analysis))


@pytest.fixture
def fake_llm() -> Any:
    def install(analysis: dict[str, Any] | None = None, status: str = "ok") -> FakeGroqService:
        service = FakeGroqService(analysis, status)
        set_groq_service(service)  # type: ignore[arg-type]
        return service

    return install
