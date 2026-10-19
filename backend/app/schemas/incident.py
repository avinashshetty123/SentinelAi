from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from app.models.enums import DataSource, IncidentStatus, NoteKind, RiskLevel
from app.schemas.common import ORMModel
from app.schemas.event import EventOut


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=4000)
    severity: RiskLevel
    risk_score: int | None = Field(default=None, ge=0, le=100)
    evidence_summary: str = Field(default="", max_length=4000)
    scan_id: uuid.UUID | None = None
    event_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    severity: RiskLevel | None = None
    status: IncidentStatus | None = None
    resolution_notes: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def _non_empty(self) -> IncidentUpdate:
        if not self.model_fields_set:
            raise ValueError("at least one field must be provided")
        return self


class NoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class LinkEventsRequest(BaseModel):
    event_ids: list[uuid.UUID] = Field(min_length=1, max_length=50)


class NoteOut(ORMModel):
    id: uuid.UUID
    created_at: datetime
    author: str
    kind: NoteKind
    body: str


class IncidentSummaryOut(ORMModel):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    title: str
    severity: RiskLevel
    risk_score: int | None
    status: IncidentStatus
    source: DataSource
    scan_id: uuid.UUID | None


class TimelineEntry(BaseModel):
    at: datetime
    kind: Literal["created", "status_change", "update", "note", "ai_summary", "event", "audit"]
    title: str
    detail: str | None = None
    actor: str | None = None
    ref_id: uuid.UUID | None = None


class AuditOut(ORMModel):
    id: uuid.UUID
    created_at: datetime
    actor: str
    action: str
    details: dict[str, Any]
    request_id: str | None


class IncidentDetail(IncidentSummaryOut):
    description: str
    evidence_summary: str
    resolution_notes: str | None
    resolved_at: datetime | None
    created_by: str
    demo_run_id: uuid.UUID | None
    notes: list[NoteOut]
    events: list[EventOut]
    timeline: list[TimelineEntry] = Field(default_factory=list)
    audit: list[AuditOut] = Field(default_factory=list)


class AISummaryResponse(BaseModel):
    status: str
    model: str | None = None
    note: NoteOut | None = None
    message: str
