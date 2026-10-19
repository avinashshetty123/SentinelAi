from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.core.ratelimit import rate_limit
from app.core.security import Principal, require_principal
from app.database.session import get_session
from app.models import SecurityEvent
from app.models.enums import DataSource, EventStatus, EventType, RiskLevel
from app.schemas.common import Page, PageParams
from app.schemas.event import EventOut, EventUpdate
from app.services.audit import record_audit
from app.services.events.service import event_to_dict
from app.websocket.manager import manager

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=Page[EventOut], dependencies=[Depends(rate_limit("reads"))])
async def list_events(
    params: PageParams = Depends(),
    severity: RiskLevel | None = None,
    event_type: EventType | None = None,
    source: DataSource | None = None,
    status: EventStatus | None = None,
    q: str | None = None,
    _: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> Page[EventOut]:
    stmt = select(SecurityEvent)
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity)
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type)
    if source:
        stmt = stmt.where(SecurityEvent.source == source)
    if status:
        stmt = stmt.where(SecurityEvent.status == status)
    if q:
        pattern = f"%{q.strip()[:100]}%"
        stmt = stmt.where(or_(SecurityEvent.description.ilike(pattern), SecurityEvent.actor.ilike(pattern)))
    total = await session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        await session.scalars(
            stmt.order_by(SecurityEvent.created_at.desc()).offset(params.offset).limit(params.page_size)
        )
    ).all()
    return Page(
        items=[EventOut.model_validate(r) for r in rows], total=total, page=params.page, page_size=params.page_size
    )


@router.get("/{event_id}", response_model=EventOut, dependencies=[Depends(rate_limit("reads"))])
async def get_event(
    event_id: uuid.UUID, _: Principal = Depends(require_principal), session: AsyncSession = Depends(get_session)
) -> EventOut:
    event = await session.get(SecurityEvent, event_id)
    if event is None:
        raise NotFoundError("Event")
    return EventOut.model_validate(event)


@router.patch("/{event_id}", response_model=EventOut, dependencies=[Depends(rate_limit("writes"))])
async def update_event(
    event_id: uuid.UUID,
    body: EventUpdate,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> EventOut:
    event = await session.get(SecurityEvent, event_id)
    if event is None:
        raise NotFoundError("Event")
    if event.status != body.status:
        record_audit(
            session,
            actor=principal.actor,
            action="event.status_changed",
            entity_type="event",
            entity_id=event.id,
            details={"from": event.status.value, "to": body.status.value},
            source=event.source,
        )
        event.status = body.status
        await session.commit()
        await session.refresh(event)
        await manager.broadcast("event.updated", event_to_dict(event))
    return EventOut.model_validate(event)
