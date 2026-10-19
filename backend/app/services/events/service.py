"""Security-event creation: validate → persist → commit → broadcast."""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database.session import get_sessionmaker
from app.models import SecurityEvent
from app.models.enums import DataSource, EventType, RiskLevel
from app.schemas.event import EventCreate, EventOut
from app.websocket.manager import manager

logger = logging.getLogger("sentinel.events")


def event_to_dict(event: SecurityEvent) -> dict[str, object]:
    return EventOut.model_validate(event).model_dump(mode="json")


async def create_event(session: AsyncSession, payload: EventCreate, *, commit: bool = True) -> SecurityEvent:
    event = SecurityEvent(**payload.model_dump())
    session.add(event)
    if commit:
        await session.commit()
        await session.refresh(event)
        await manager.broadcast("event.created", event_to_dict(event))
    else:
        await session.flush()
    return event


async def broadcast_event(event: SecurityEvent) -> None:
    await manager.broadcast("event.created", event_to_dict(event))


async def prune_event_history(session: AsyncSession) -> int:
    """Bounded history: delete the oldest events beyond EVENT_HISTORY_MAX that are not linked to incidents."""
    limit = get_settings().event_history_max
    total = await session.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    excess = total - limit
    if excess <= 0:
        return 0
    old_ids = (
        await session.scalars(
            select(SecurityEvent.id)
            .where(SecurityEvent.incident_id.is_(None))
            .order_by(SecurityEvent.created_at.asc())
            .limit(excess)
        )
    ).all()
    if not old_ids:
        return 0
    await session.execute(delete(SecurityEvent).where(SecurityEvent.id.in_(old_ids)))
    await session.commit()
    return len(old_ids)


# Throttle rate-limit events: at most one per (bucket, client) per minute.
_last_rate_event: dict[str, float] = {}


async def on_rate_limited(bucket: str, ip: str) -> None:
    import time

    key = f"{bucket}:{ip}"
    now = time.monotonic()
    if now - _last_rate_event.get(key, 0) < 60:
        return
    _last_rate_event[key] = now
    if len(_last_rate_event) > 10_000:
        _last_rate_event.clear()
    # Identify the client only by a short non-reversible tag, not its raw IP address.
    tag = uuid.uuid5(uuid.NAMESPACE_URL, ip).hex[:8]
    try:
        async with get_sessionmaker()() as session:
            await create_event(
                session,
                EventCreate(
                    event_type=EventType.RATE_LIMIT,
                    severity=RiskLevel.MEDIUM,
                    actor=f"client-{tag}",
                    description=f"Client exceeded the '{bucket}' request rate limit and was throttled.",
                    source=DataSource.APPLICATION,
                    details={"bucket": bucket},
                ),
            )
    except Exception:
        logger.warning("Failed to record rate-limit event")
