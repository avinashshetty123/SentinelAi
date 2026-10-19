from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import get_settings
from app.core.ratelimit import rate_limit
from app.core.security import Principal, require_principal, verify_token
from app.database.session import get_engine
from app.schemas.system import ClassifierStatus, LLMCheckResponse, ProviderStatus, SystemStatus
from app.services.detection.classifier import classifier_load_error, get_classifier
from app.services.detection.message_rules import RULE_VERSION
from app.services.detection.url_analyzer import URL_RULE_VERSION
from app.services.llm.groq_service import get_groq_service
from app.services.reputation.provider import get_reputation_provider
from app.services.scoring.engine import SCORING_VERSION
from app.websocket.manager import manager

router = APIRouter(tags=["system"])


async def database_ok() -> bool:
    try:
        async with get_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


@router.get("/health/ready", summary="Readiness: dependencies reachable")
async def ready() -> JSONResponse:
    ok = await database_ok()
    return JSONResponse(
        status_code=200 if ok else 503,
        content={"status": "ready" if ok else "not_ready", "database": "ok" if ok else "unavailable"},
    )


@router.get("/auth/session", summary="Report auth mode and whether the supplied token is valid")
async def auth_session(request: Request) -> dict[str, object]:
    settings = get_settings()
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else None
    return {
        "auth_mode": settings.auth_mode,
        "authenticated": verify_token(token, settings),
        "token_required": settings.auth_mode == "token",
    }


@router.get("/system/status", response_model=SystemStatus, dependencies=[Depends(rate_limit("reads"))])
async def system_status(_: Principal = Depends(require_principal)) -> SystemStatus:
    settings = get_settings()
    clf = get_classifier()
    groq_state = "active" if settings.groq_active else ("disabled" if not settings.groq_enabled else "not_configured")
    reputation = get_reputation_provider()
    return SystemStatus(
        app=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
        database="ok" if await database_ok() else "unavailable",
        groq=ProviderStatus(
            enabled=settings.groq_enabled,
            configured=settings.groq_configured,
            model=settings.groq_model,
            status=groq_state,
        ),
        classifier=ClassifierStatus(
            available=clf is not None and settings.classifier_enabled,
            model_version=clf.model_version if clf else None,
            reason=None if clf else (classifier_load_error() or "disabled"),
            test_metrics=clf.metrics_summary if clf else {},
            dataset=clf.dataset if clf else {},
        ),
        reputation={"provider": reputation.name, "status": "active" if reputation.name != "none" else "not_configured"},
        websocket_clients=manager.client_count,
        auth_mode=settings.auth_mode,
        demo_mode=settings.demo_mode_enabled,
        rate_limiting=settings.rate_limit_enabled,
        privacy={
            "raw_text_stored": False,
            "finding_excerpts_stored": settings.store_finding_excerpts,
            "ai_summaries_stored": settings.store_ai_summaries,
            "scan_retention_days": settings.scan_retention_days,
        },
        thresholds={
            "medium": settings.risk_threshold_medium,
            "high": settings.risk_threshold_high,
            "critical": settings.risk_threshold_critical,
        },
        versions={"rules": RULE_VERSION, "url_rules": URL_RULE_VERSION, "scoring": SCORING_VERSION},
        server_time=datetime.now(UTC),
    )


@router.post(
    "/system/llm-check",
    response_model=LLMCheckResponse,
    dependencies=[Depends(rate_limit("scans"))],
    summary="Send a tiny synthetic request to Groq to verify credentials and model access",
)
async def llm_check(_: Principal = Depends(require_principal)) -> LLMCheckResponse:
    outcome = await get_groq_service().analyze_message(
        "[SYNTHETIC CONNECTIVITY CHECK] Your parcel is waiting. Pay a small redelivery fee today.", "sms", []
    )
    messages = {
        "ok": "Groq responded with schema-valid structured output.",
        "disabled": "Groq is disabled (GROQ_ENABLED=false).",
        "not_configured": "GROQ_API_KEY is not set.",
        "auth_error": "Groq rejected the credentials or model access.",
        "invalid_output": "Groq responded but the output failed schema validation.",
    }
    return LLMCheckResponse(
        status=outcome.status,
        model=outcome.model,
        latency_ms=outcome.latency_ms,
        message=messages.get(outcome.status, f"Groq call failed: {outcome.status}."),
    )
