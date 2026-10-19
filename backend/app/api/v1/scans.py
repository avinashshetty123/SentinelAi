from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import NotFoundError
from app.core.ratelimit import rate_limit
from app.core.security import Principal, require_principal
from app.database.session import get_session
from app.models import Scan
from app.models.enums import DataSource, RiskLevel, ScanKind
from app.schemas.common import Page, PageParams
from app.schemas.scan import MessageScanRequest, ScanDetail, ScanResult, ScanSummary, UrlScanRequest
from app.services.analysis import AnalysisContext, analyze_message, analyze_url_scan
from app.services.audit import record_audit

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post(
    "/message",
    response_model=ScanResult,
    dependencies=[Depends(rate_limit("scans"))],
    summary="Analyze a message for scam / social-engineering indicators",
)
async def scan_message(
    body: MessageScanRequest,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> ScanResult:
    return await analyze_message(session, body, AnalysisContext(actor=principal.actor))


@router.post(
    "/url",
    response_model=ScanResult,
    dependencies=[Depends(rate_limit("scans"))],
    summary="Analyze a URL offline (the URL is never visited)",
)
async def scan_url(
    body: UrlScanRequest,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> ScanResult:
    return await analyze_url_scan(session, body, AnalysisContext(actor=principal.actor))


@router.get("", response_model=Page[ScanSummary], dependencies=[Depends(rate_limit("reads"))])
async def list_scans(
    params: PageParams = Depends(),
    kind: ScanKind | None = None,
    risk_level: RiskLevel | None = None,
    source: DataSource | None = None,
    _: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> Page[ScanSummary]:
    stmt = select(Scan)
    if kind:
        stmt = stmt.where(Scan.kind == kind)
    if risk_level:
        stmt = stmt.where(Scan.risk_level == risk_level)
    if source:
        stmt = stmt.where(Scan.source == source)
    total = await session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        await session.scalars(stmt.order_by(Scan.created_at.desc()).offset(params.offset).limit(params.page_size))
    ).all()
    return Page(
        items=[ScanSummary.model_validate(r) for r in rows], total=total, page=params.page, page_size=params.page_size
    )


@router.get("/{scan_id}", response_model=ScanDetail, dependencies=[Depends(rate_limit("reads"))])
async def get_scan(
    scan_id: uuid.UUID, _: Principal = Depends(require_principal), session: AsyncSession = Depends(get_session)
) -> ScanDetail:
    scan = await session.scalar(select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings)))
    if scan is None:
        raise NotFoundError("Scan")
    return ScanDetail.model_validate(scan)


@router.delete("/{scan_id}", status_code=204, dependencies=[Depends(rate_limit("writes"))], response_class=Response)
async def delete_scan(
    scan_id: uuid.UUID, principal: Principal = Depends(require_principal), session: AsyncSession = Depends(get_session)
) -> Response:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError("Scan")
    await session.delete(scan)
    record_audit(
        session,
        actor=principal.actor,
        action="scan.deleted",
        entity_type="scan",
        entity_id=scan_id,
        details={"kind": scan.kind.value},
    )
    await session.commit()
    return Response(status_code=204)
