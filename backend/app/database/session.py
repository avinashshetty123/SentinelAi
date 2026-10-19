"""Async engine and session management."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.config import Settings, get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def build_engine(settings: Settings) -> AsyncEngine:
    kwargs: dict[str, Any] = {"echo": settings.database_echo}
    if settings.is_sqlite:
        if ":memory:" in settings.database_url:
            kwargs.update(poolclass=StaticPool, connect_args={"check_same_thread": False})
    else:
        kwargs.update(pool_size=settings.database_pool_size, max_overflow=5, pool_pre_ping=True, pool_recycle=1800)
    engine = create_async_engine(settings.database_url, **kwargs)
    if settings.is_sqlite:

        @event.listens_for(engine.sync_engine, "connect")
        def _enable_fk(dbapi_connection: Any, _: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def init_engine(settings: Settings | None = None) -> AsyncEngine:
    global _engine, _sessionmaker
    settings = settings or get_settings()
    _engine = build_engine(settings)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False, autoflush=False)
    return _engine


def get_engine() -> AsyncEngine:
    if _engine is None:
        init_engine()
    assert _engine is not None
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        init_engine()
    assert _sessionmaker is not None
    return _sessionmaker


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


async def get_session() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        yield session
