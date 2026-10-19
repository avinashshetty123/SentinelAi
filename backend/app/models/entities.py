"""SQLAlchemy ORM models.

Raw message text is intentionally NOT a column anywhere. Finding excerpts are stored only when
STORE_FINDING_EXCERPTS=true.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, CreatedAtMixin, JSONType, UTCDateTime, UUIDPrimaryKeyMixin, utcnow
from app.models.enums import (
    DataSource,
    DemoRunStatus,
    EventStatus,
    EventType,
    IncidentStatus,
    NoteKind,
    RiskLevel,
    ScanKind,
)


def enum_col(enum_cls: type[StrEnum], name: str) -> SAEnum:
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        length=32,
        values_callable=lambda e: [m.value for m in e],
    )


class DemoRun(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "demo_runs"

    scenario_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[DemoRunStatus] = mapped_column(enum_col(DemoRunStatus, "demo_run_status"))
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)


class Scan(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_score_range"),
        Index("ix_scans_level_created", "risk_level", "created_at"),
    )

    kind: Mapped[ScanKind] = mapped_column(enum_col(ScanKind, "scan_kind"), index=True)
    content_type: Mapped[str] = mapped_column(String(32))
    source: Mapped[DataSource] = mapped_column(
        enum_col(DataSource, "data_source"), index=True, default=DataSource.APPLICATION
    )
    demo_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("demo_runs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[RiskLevel] = mapped_column(enum_col(RiskLevel, "risk_level"))
    evidence_strength: Mapped[str] = mapped_column(String(16))
    summary: Mapped[str] = mapped_column(Text)
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations: Mapped[list[str]] = mapped_column(JSONType, default=list)
    limitations: Mapped[list[str]] = mapped_column(JSONType, default=list)
    score_breakdown: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    llm_status: Mapped[str] = mapped_column(String(32))
    llm_model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    sent_to_llm: Mapped[bool] = mapped_column(Boolean, default=False)
    classifier_status: Mapped[str] = mapped_column(String(32))
    classifier_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    classifier_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    rule_version: Mapped[str] = mapped_column(String(32))
    scoring_version: Mapped[str] = mapped_column(String(32))
    input_length: Mapped[int] = mapped_column(Integer)
    url_count: Mapped[int] = mapped_column(Integer, default=0)
    # URL scans store scheme + host only (paths/queries may contain tokens).
    target_display: Mapped[str | None] = mapped_column(String(300), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)

    findings: Mapped[list[ScanFinding]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ScanFinding.position",
    )


class ScanFinding(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "scan_findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(160))
    category: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(24))
    weight: Mapped[int] = mapped_column(Integer)
    points: Mapped[float] = mapped_column(Float)
    explanation: Mapped[str] = mapped_column(Text)
    evidence_excerpt: Mapped[str | None] = mapped_column(String(300), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Incident(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)", name="incident_risk_range"),
        Index("ix_incidents_status_created", "status", "created_at"),
    )

    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[RiskLevel] = mapped_column(enum_col(RiskLevel, "incident_severity"), index=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_summary: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[IncidentStatus] = mapped_column(
        enum_col(IncidentStatus, "incident_status"), default=IncidentStatus.OPEN
    )
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    source: Mapped[DataSource] = mapped_column(
        enum_col(DataSource, "incident_source"), index=True, default=DataSource.APPLICATION
    )
    demo_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("demo_runs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by: Mapped[str] = mapped_column(String(80), default="operator")

    notes: Mapped[list[IncidentNote]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="IncidentNote.created_at",
    )
    events: Mapped[list[SecurityEvent]] = relationship(back_populates="incident", order_by="SecurityEvent.created_at")


class IncidentNote(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "incident_notes"

    incident_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(80))
    kind: Mapped[NoteKind] = mapped_column(enum_col(NoteKind, "note_kind"), default=NoteKind.NOTE)
    body: Mapped[str] = mapped_column(Text)

    incident: Mapped[Incident] = relationship(back_populates="notes")


class SecurityEvent(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint("risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)", name="event_risk_range"),
        Index("ix_security_events_source_created", "source", "created_at"),
    )

    event_type: Mapped[EventType] = mapped_column(enum_col(EventType, "event_type"), index=True)
    severity: Mapped[RiskLevel] = mapped_column(enum_col(RiskLevel, "event_severity"), index=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(String(500))
    source: Mapped[DataSource] = mapped_column(enum_col(DataSource, "event_source"))
    status: Mapped[EventStatus] = mapped_column(enum_col(EventStatus, "event_status"), default=EventStatus.NEW)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    demo_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("demo_runs.id", ondelete="SET NULL"), nullable=True, index=True
    )

    incident: Mapped[Incident | None] = relationship(back_populates="events")


class AuditLog(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_entity", "entity_type", "entity_id"),)

    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity_type: Mapped[str] = mapped_column(String(32))
    entity_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[DataSource] = mapped_column(enum_col(DataSource, "audit_source"), default=DataSource.APPLICATION)
