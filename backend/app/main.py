"""SentinelAI FastAPI application entry point."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, log_fields
from app.core.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from app.core.ratelimit import set_rate_limit_hook
from app.database.session import dispose_engine, init_engine
from app.services.demo.runner import simulator
from app.services.detection.classifier import load_classifier
from app.services.events.service import on_rate_limited
from app.services.llm.groq_service import get_groq_service
from app.services.reputation.provider import init_reputation_provider
from app.services.retention import retention_loop

logger = logging.getLogger("sentinel")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    init_engine(settings)
    if settings.classifier_enabled:
        load_classifier(settings.classifier_path)
    init_reputation_provider()
    set_rate_limit_hook(on_rate_limited)
    retention_task = asyncio.create_task(retention_loop()) if settings.app_env != "test" else None
    log_fields(
        logger,
        logging.INFO,
        "startup",
        env=settings.app_env,
        auth_mode=settings.auth_mode,
        groq=("active" if settings.groq_active else "inactive"),
        model=settings.groq_model,
        demo_mode=settings.demo_mode_enabled,
    )
    try:
        yield
    finally:
        if retention_task:
            retention_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await retention_task
        await simulator.stop()
        await get_groq_service().aclose()
        set_rate_limit_hook(None)
        await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="SentinelAI API",
        version=settings.app_version,
        description="Explainable scam, URL and security-event analysis. Risk scores are evidence indices "
        "(0–100), not probabilities.",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    register_exception_handlers(app)

    # Order: outermost first at runtime is the LAST added.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_origin_regex=settings.cors_origin_regex,
        allow_credentials=False,  # bearer tokens only; no cookies
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Retry-After"],
        max_age=600,
    )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(RequestContextMiddleware, hsts=settings.app_env == "production")

    @app.get("/health", tags=["system"], summary="Liveness: the process is up")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": settings.app_version}

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {"service": "SentinelAI API", "docs": "/docs", "health": "/health"}

    app.include_router(api_router)
    return app


app = create_app()
