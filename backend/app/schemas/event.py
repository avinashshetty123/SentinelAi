from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import DataSource, EventStatus, EventType, RiskLevel
from app.schemas.common import ORMModel


class EventOut(ORMModel):
    id: uuid.UUID
    created_at: datetime
    event_type: EventType
    severity: RiskLevel
    risk_score: int | None
    actor: str
    description: str
    source: DataSource
    status: EventStatus
    details: dict[str, Any]
    scan_id: uuid.UUID | None
    incident_id: uuid.UUID | None
    demo_run_id: uuid.UUID | None


class EventCreate(BaseModel):
    """Internal: validated before persistence and broadcast."""

    event_type: EventType
    severity: RiskLevel
    risk_score: int | None = Field(default=None, ge=0, le=100)
    actor: str = Field(max_length=120)
    description: str = Field(max_length=500)
    source: DataSource
    details: dict[str, Any] = Field(default_factory=dict)
    scan_id: uuid.UUID | None = None
    incident_id: uuid.UUID | None = None
    demo_run_id: uuid.UUID | None = None


class EventUpdate(BaseModel):
    status: EventStatus


class SimulatedEventRequest(BaseModel):
    event_type: EventType = Field(description="Synthetic event to generate (simulation source)")
