"""Incident lifecycle: creation, updates with audit trail, notes, event linking and timelines."""

from __future__ import annotations

import uuid

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import AppError, NotFoundError
from app.database.base import utcnow
from app.models import AuditLog, Incident, IncidentNote, Scan, SecurityEvent
from app.models.enums import DataSource, EventStatus, EventType, IncidentStatus, NoteKind, RiskLevel
from app.schemas.common import PageParams
from app.schemas.event import EventCreate
from app.schemas.incident import (
    AuditOut,
    IncidentCreate,
    IncidentDetail,
    IncidentUpdate,
    NoteOut,
    TimelineEntry,
)
from app.services.audit import record_audit
from app.services.events.service import create_event, event_to_dict
from app.websocket.manager import manager

CLOSED_STATUSES = {IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE}


def _incident_brief(incident: Incident) -> dict[str, object]:
    return {
        "id": str(incident.id),
        "title": incident.title,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "source": incident.source.value,
        "risk_score": incident.risk_score,
    }


async def _link_events(session: AsyncSession, incident: Incident, event_ids: list[uuid.UUID]) -> int:
    if not event_ids:
        return 0
    events = (await session.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(event_ids)))).all()
    if len(events) != len(set(event_ids)):
        raise AppError(422, "validation_error", "One or more event IDs do not exist")
    for event in events:
        if event.incident_id and event.incident_id != incident.id:
            raise AppError(409, "conflict", "An event is already linked to another incident")
        event.incident_id = incident.id
        event.status = EventStatus.LINKED
    return len(events)


async def create_incident_record(
    session: AsyncSession,
    *,
    title: str,
    description: str,
    severity: RiskLevel,
    risk_score: int | None,
    evidence_summary: str,
    scan_id: uuid.UUID | None,
    event_ids: list[uuid.UUID],
    actor: str,
    source: DataSource = DataSource.APPLICATION,
    demo_run_id: uuid.UUID | None = None,
) -> Incident:
    """Adds an incident within the caller's transaction (no commit)."""
    if scan_id is not None and await session.get(Scan, scan_id) is None:
        raise AppError(422, "validation_error", "scan_id does not exist")
    incident = Incident(
        title=title,
        description=description,
        severity=severity,
        risk_score=risk_score,
        evidence_summary=evidence_summary,
        scan_id=scan_id,
        created_by=actor,
        source=source,
        demo_run_id=demo_run_id,
        status=IncidentStatus.OPEN,
    )
    session.add(incident)
    await session.flush()
    linked = await _link_events(session, incident, event_ids)
    record_audit(
        session,
        actor=actor,
        action="incident.created",
        entity_type="incident",
        entity_id=incident.id,
        details={"severity": severity.value, "linked_events": linked, "scan_id": str(scan_id) if scan_id else None},
        source=source,
    )
    return incident


async def incident_created_side_effects(session: AsyncSession, incident: Incident) -> None:
    """After commit: emit an incident_created security event and broadcast."""
    await create_event(
        session,
        EventCreate(
            event_type=EventType.INCIDENT_CREATED,
            severity=incident.severity,
            risk_score=incident.risk_score,
            actor=incident.created_by,
            description=f"Incident opened: {incident.title}"[:500],
            source=incident.source,
            incident_id=incident.id,
            scan_id=incident.scan_id,
            demo_run_id=incident.demo_run_id,
        ),
    )
    await manager.broadcast("incident.created", _incident_brief(incident))


async def create_incident(
    session: AsyncSession,
    data: IncidentCreate,
    actor: str,
    source: DataSource = DataSource.APPLICATION,
    demo_run_id: uuid.UUID | None = None,
) -> Incident:
    incident = await create_incident_record(
        session,
        title=data.title,
        description=data.description,
        severity=data.severity,
        risk_score=data.risk_score,
        evidence_summary=data.evidence_summary,
        scan_id=data.scan_id,
        event_ids=data.event_ids,
        actor=actor,
        source=source,
        demo_run_id=demo_run_id,
    )
    await session.commit()
    await session.refresh(incident)
    await incident_created_side_effects(session, incident)
    return incident


async def get_incident_or_404(session: AsyncSession, incident_id: uuid.UUID) -> Incident:
    incident = await session.scalar(
        select(Incident)
        .where(Incident.id == incident_id)
        .options(selectinload(Incident.notes), selectinload(Incident.events))
    )
    if incident is None:
        raise NotFoundError("Incident")
    return incident


async def update_incident(session: AsyncSession, incident_id: uuid.UUID, data: IncidentUpdate, actor: str) -> Incident:
    incident = await get_incident_or_404(session, incident_id)
    changes: dict[str, dict[str, object]] = {}
    fields = data.model_dump(exclude_unset=True)

    new_status = fields.get("status")
    if new_status is not None and new_status != incident.status:
        if new_status in CLOSED_STATUSES:
            notes = fields.get("resolution_notes") or incident.resolution_notes
            if not notes or not str(notes).strip():
                raise AppError(
                    422,
                    "validation_error",
                    "resolution_notes are required to resolve or close an incident as false positive",
                )
            incident.resolved_at = utcnow()
        elif incident.status in CLOSED_STATUSES:
            incident.resolved_at = None  # reopened
        changes["status"] = {"from": incident.status.value, "to": new_status.value}
        incident.status = new_status

    for name in ("title", "description", "severity", "resolution_notes"):
        if name in fields and fields[name] is not None and getattr(incident, name) != fields[name]:
            old = getattr(incident, name)
            changes[name] = {
                "from": getattr(old, "value", old) if name == "severity" else None,
                "to": getattr(fields[name], "value", None) if name == "severity" else None,
            }
            setattr(incident, name, fields[name])

    if not changes:
        return incident
    incident.updated_at = utcnow()
    record_audit(
        session,
        actor=actor,
        action="incident.updated",
        entity_type="incident",
        entity_id=incident.id,
        details={"changes": changes},
        source=incident.source,
    )
    await session.commit()

    if "status" in changes and incident.status in CLOSED_STATUSES:
        await create_event(
            session,
            EventCreate(
                event_type=EventType.INCIDENT_RESOLVED,
                severity=RiskLevel.LOW,
                risk_score=incident.risk_score,
                actor=actor,
                description=f"Incident {incident.status.value.replace('_', ' ').lower()}: {incident.title}"[:500],
                source=incident.source,
                incident_id=incident.id,
                demo_run_id=incident.demo_run_id,
            ),
        )
    incident = await get_incident_or_404(session, incident_id)
    await manager.broadcast("incident.updated", _incident_brief(incident))
    return incident


async def add_note(
    session: AsyncSession, incident_id: uuid.UUID, body: str, actor: str, kind: NoteKind = NoteKind.NOTE
) -> IncidentNote:
    incident = await get_incident_or_404(session, incident_id)
    note = IncidentNote(incident_id=incident.id, author=actor, body=body.strip(), kind=kind)
    session.add(note)
    incident.updated_at = utcnow()
    record_audit(
        session,
        actor=actor,
        action="incident.note_added",
        entity_type="incident",
        entity_id=incident.id,
        details={"kind": kind.value, "length": len(body)},
        source=incident.source,
    )
    await session.commit()
    await session.refresh(note)
    await manager.broadcast("incident.updated", _incident_brief(incident))
    return note


async def link_events(
    session: AsyncSession, incident_id: uuid.UUID, event_ids: list[uuid.UUID], actor: str
) -> Incident:
    incident = await get_incident_or_404(session, incident_id)
    linked = await _link_events(session, incident, event_ids)
    incident.updated_at = utcnow()
    record_audit(
        session,
        actor=actor,
        action="incident.events_linked",
        entity_type="incident",
        entity_id=incident.id,
        details={"event_ids": [str(e) for e in event_ids], "count": linked},
        source=incident.source,
    )
    await session.commit()
    session.expire_all()
    incident = await get_incident_or_404(session, incident_id)
    for event in incident.events:
        if event.id in event_ids:
            await manager.broadcast("event.updated", event_to_dict(event))
    return incident


async def list_incidents(
    session: AsyncSession,
    params: PageParams,
    status: IncidentStatus | None,
    severity: RiskLevel | None,
    source: DataSource | None,
    q: str | None,
) -> tuple[list[Incident], int]:
    stmt = select(Incident)
    if status:
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if source:
        stmt = stmt.where(Incident.source == source)
    if q:
        pattern = f"%{q.strip()[:100]}%"
        stmt = stmt.where(or_(Incident.title.ilike(pattern), Incident.description.ilike(pattern)))
    total = await session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        await session.scalars(stmt.order_by(Incident.created_at.desc()).offset(params.offset).limit(params.page_size))
    ).all()
    return list(rows), total


_ACTION_TITLES = {
    "incident.created": "Incident created",
    "incident.updated": "Incident updated",
    "incident.note_added": "Note added",
    "incident.events_linked": "Events linked",
    "incident.ai_summary": "AI summary requested",
}


async def incident_detail(session: AsyncSession, incident_id: uuid.UUID) -> IncidentDetail:
    incident = await get_incident_or_404(session, incident_id)
    audits = (
        await session.scalars(
            select(AuditLog)
            .where(AuditLog.entity_type == "incident", AuditLog.entity_id == incident.id)
            .order_by(AuditLog.created_at.asc())
        )
    ).all()

    timeline: list[TimelineEntry] = []
    for a in audits:
        if a.action == "incident.note_added":
            continue  # represented by the note itself
        changes = a.details.get("changes", {}) if isinstance(a.details, dict) else {}
        if a.action == "incident.created":
            timeline.append(
                TimelineEntry(
                    at=a.created_at,
                    kind="created",
                    title="Incident created",
                    detail=f"Severity {a.details.get('severity')}",
                    actor=a.actor,
                )
            )
        elif "status" in changes:
            st = changes["status"]
            timeline.append(
                TimelineEntry(
                    at=a.created_at,
                    kind="status_change",
                    title=f"Status {st.get('from')} → {st.get('to')}",
                    actor=a.actor,
                    detail=", ".join(k for k in changes if k != "status") or None,
                )
            )
        else:
            timeline.append(
                TimelineEntry(
                    at=a.created_at,
                    kind="update" if a.action == "incident.updated" else "audit",
                    title=_ACTION_TITLES.get(a.action, a.action),
                    detail=", ".join(changes) or None,
                    actor=a.actor,
                )
            )
    for note in incident.notes:
        timeline.append(
            TimelineEntry(
                at=note.created_at,
                kind="ai_summary" if note.kind == NoteKind.AI_SUMMARY else "note",
                title="AI summary added" if note.kind == NoteKind.AI_SUMMARY else "Note",
                detail=note.body[:280],
                actor=note.author,
                ref_id=note.id,
            )
        )
    for event in incident.events:
        if event.event_type == EventType.INCIDENT_CREATED:
            continue  # already represented by the audit-based "Incident created" entry
        timeline.append(
            TimelineEntry(
                at=event.created_at,
                kind="event",
                title=event.event_type.value.replace("_", " ").capitalize(),
                detail=event.description,
                actor=event.actor,
                ref_id=event.id,
            )
        )
    timeline.sort(key=lambda t: t.at)

    detail = IncidentDetail.model_validate(incident, from_attributes=True)
    detail.notes = [NoteOut.model_validate(n) for n in incident.notes]
    detail.timeline = timeline
    detail.audit = [AuditOut.model_validate(a) for a in audits]
    return detail
