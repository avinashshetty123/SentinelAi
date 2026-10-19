from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import request_id_ctx
from app.models import AuditLog
from app.models.enums import DataSource


def record_audit(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: uuid.UUID | None,
    details: dict[str, Any] | None = None,
    source: DataSource = DataSource.APPLICATION,
) -> AuditLog:
    """Adds an audit record to the current transaction (committed with the change it describes)."""
    entry = AuditLog(
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details or {},
        request_id=request_id_ctx.get(),
        source=source,
    )
    session.add(entry)
    return entry
