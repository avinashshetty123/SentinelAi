"""Privacy-aware retention: scans past their expiry are deleted (findings cascade)."""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import delete

from app.core.logging import log_fields
from app.database.base import utcnow
from app.database.session import get_sessionmaker
from app.models import Scan
from app.services.events.service import prune_event_history

logger = logging.getLogger("sentinel.retention")


async def purge_expired() -> dict[str, int]:
    async with get_sessionmaker()() as session:
        result = await session.execute(delete(Scan).where(Scan.expires_at < utcnow()))
        await session.commit()
        scans = result.rowcount or 0  # type: ignore[attr-defined]
        events = await prune_event_history(session)
    if scans or events:
        log_fields(logger, logging.INFO, "retention_purge", scans=scans, events=events)
    return {"scans": scans, "events": events}


async def retention_loop(interval_seconds: int = 3600) -> None:
    while True:
        try:
            await purge_expired()
        except Exception:
            logger.warning("Retention purge failed")
        await asyncio.sleep(interval_seconds)
