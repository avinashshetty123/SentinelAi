"""Authentication, configuration safety and rate limiting."""

from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.core.config import Settings
from app.models import SecurityEvent

TOKEN = "t" * 32


async def test_token_mode_requires_bearer(client, settings_env) -> None:
    settings_env(AUTH_MODE="token", ADMIN_API_TOKEN=TOKEN)
    assert (await client.get("/api/v1/incidents")).status_code == 401
    assert (await client.get("/api/v1/incidents", headers={"Authorization": "Bearer wrong"})).status_code == 401
    r = await client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200
    # Mutations are protected as well.
    assert (await client.post("/api/v1/scans/message", json={"text": "hello"})).status_code == 401
    # Liveness/readiness and auth-session stay public.
    assert (await client.get("/health")).status_code == 200
    assert (await client.get("/api/v1/health/ready")).status_code == 200
    session = (await client.get("/api/v1/auth/session")).json()
    assert session == {"auth_mode": "token", "authenticated": False, "token_required": True}


def test_production_refuses_open_mode_without_acknowledgement() -> None:
    with pytest.raises(ValidationError):
        Settings(app_env="production", auth_mode="open", database_url="sqlite+aiosqlite://")
    Settings(app_env="production", auth_mode="open", allow_open_mode_in_production=True,
             database_url="sqlite+aiosqlite://")


def test_token_mode_requires_strong_token() -> None:
    with pytest.raises(ValidationError):
        Settings(auth_mode="token", admin_api_token="short", database_url="sqlite+aiosqlite://")


def test_thresholds_must_be_ordered() -> None:
    with pytest.raises(ValidationError):
        Settings(risk_threshold_medium=60, risk_threshold_high=50, database_url="sqlite+aiosqlite://")


def test_database_url_normalization() -> None:
    s = Settings(database_url="postgres://u:p@host:5432/db?sslmode=require")
    assert s.database_url == "postgresql+asyncpg://u:p@host:5432/db?ssl=require"


async def test_rate_limit_returns_429_and_records_event(client, settings_env, session) -> None:
    settings_env(RATE_LIMIT_ENABLED="true", RATE_LIMIT_SCANS_PER_MINUTE="2")
    codes = [(await client.post("/api/v1/scans/url", json={"url": "https://example.com"})).status_code
             for _ in range(3)]
    assert codes == [200, 200, 429]
    r = await client.post("/api/v1/scans/url", json={"url": "https://example.com"})
    assert r.headers.get("retry-after") and r.json()["error"]["code"] == "rate_limited"
    for _ in range(20):  # the rate-limit event is recorded asynchronously
        await session.rollback()  # start a fresh read snapshot
        events = (await session.scalars(select(SecurityEvent))).all()
        if events:
            break
        await asyncio.sleep(0.05)
    assert any(e.event_type.value == "rate_limit" for e in events)
    assert all("127.0.0.1" not in e.actor and "testclient" not in e.actor for e in events)


async def test_demo_endpoints_disabled(client, settings_env) -> None:
    settings_env(DEMO_MODE_ENABLED="false")
    r = await client.get("/api/v1/demo/scenarios")
    assert r.status_code == 403 and r.json()["error"]["code"] == "demo_disabled"


async def test_cors_allows_only_configured_origin(client) -> None:
    ok = await client.options("/api/v1/scans", headers={"Origin": "http://localhost:3000",
                                                        "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:3000"
    bad = await client.options("/api/v1/scans", headers={"Origin": "https://evil.example",
                                                         "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in bad.headers
