from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ratelimit import rate_limit
from app.core.security import Principal, require_principal
from app.database.session import get_session
from app.models import Incident, Scan, SecurityEvent
from app.models.enums import DataSource, IncidentStatus, RiskLevel
from app.schemas.event import EventOut
from app.schemas.incident import IncidentSummaryOut
from app.schemas.scan import ScanSummary
from app.schemas.system import ActivityBucket, DashboardActivity, DashboardSummary, RiskDistribution

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

OPEN_STATUSES = (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)


@router.get("/summary", response_model=DashboardSummary, dependencies=[Depends(rate_limit("reads"))])
async def summary(
    _: Principal = Depends(require_principal), session: AsyncSession = Depends(get_session)
) -> DashboardSummary:
    since = datetime.now(UTC) - timedelta(hours=24)
    total = await session.scalar(select(func.count()).select_from(Scan)) or 0
    last_24h = await session.scalar(select(func.count()).select_from(Scan).where(Scan.created_at >= since)) or 0
    dist_rows = (await session.execute(select(Scan.risk_level, func.count()).group_by(Scan.risk_level))).all()
    distribution = RiskDistribution(**{RiskLevel(level).value: count for level, count in dist_rows})
    open_incidents = (
        await session.scalar(select(func.count()).select_from(Incident).where(Incident.status.in_(OPEN_STATUSES))) or 0
    )
    events_24h = (
        await session.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.created_at >= since))
        or 0
    )
    demo_present = bool(
        await session.scalar(select(func.count()).select_from(Scan).where(Scan.source != DataSource.APPLICATION))
        or await session.scalar(
            select(func.count()).select_from(SecurityEvent).where(SecurityEvent.source != DataSource.APPLICATION)
        )
    )
    recent_scans = (await session.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(6))).all()
    recent_events = (
        await session.scalars(select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(10))
    ).all()
    open_list = (
        await session.scalars(
            select(Incident).where(Incident.status.in_(OPEN_STATUSES)).order_by(Incident.created_at.desc()).limit(6)
        )
    ).all()
    return DashboardSummary(
        total_scans=total,
        scans_24h=last_24h,
        high_risk_scans=distribution.HIGH + distribution.CRITICAL,
        critical_scans=distribution.CRITICAL,
        open_incidents=open_incidents,
        events_24h=events_24h,
        demo_records_present=demo_present,
        risk_distribution=distribution,
        recent_scans=[ScanSummary.model_validate(s) for s in recent_scans],
        recent_events=[EventOut.model_validate(e) for e in recent_events],
        open_incident_list=[IncidentSummaryOut.model_validate(i) for i in open_list],
        provenance_note="All figures come from records stored by this deployment. Records with source "
        "'demo' or 'simulation' are synthetic and labelled as such.",
    )


@router.get("/activity", response_model=DashboardActivity, dependencies=[Depends(rate_limit("reads"))])
async def activity(
    range_: Literal["24h", "7d"] = Query(default="24h", alias="range"),
    _: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> DashboardActivity:
    now = datetime.now(UTC)
    if range_ == "24h":
        step, count, bucket = timedelta(hours=1), 24, "hour"
        start = now.replace(minute=0, second=0, microsecond=0) - step * (count - 1)
    else:
        step, count, bucket = timedelta(days=1), 7, "day"
        start = now.replace(hour=0, minute=0, second=0, microsecond=0) - step * (count - 1)
    buckets = [ActivityBucket(start=start + step * i) for i in range(count)]

    def index_for(ts: datetime) -> int | None:
        idx = int((ts - start) // step)
        return idx if 0 <= idx < count else None

    # Aggregated in Python for database portability; bounded to the selected window.
    for created, level in (
        await session.execute(select(Scan.created_at, Scan.risk_level).where(Scan.created_at >= start))
    ).all():
        i = index_for(created)
        if i is not None:
            name = RiskLevel(level).value
            setattr(buckets[i], name, getattr(buckets[i], name) + 1)
    for (created,) in (
        await session.execute(select(SecurityEvent.created_at).where(SecurityEvent.created_at >= start))
    ).all():
        i = index_for(created)
        if i is not None:
            buckets[i].events += 1
    return DashboardActivity(range=range_, bucket=bucket, buckets=buckets)
