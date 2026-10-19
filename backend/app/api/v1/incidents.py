from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ratelimit import rate_limit
from app.core.security import Principal, require_principal
from app.database.session import get_session
from app.models.enums import DataSource, IncidentStatus, NoteKind, RiskLevel
from app.schemas.common import Page, PageParams
from app.schemas.incident import (
    AISummaryResponse,
    IncidentCreate,
    IncidentDetail,
    IncidentSummaryOut,
    IncidentUpdate,
    LinkEventsRequest,
    NoteCreate,
    NoteOut,
)
from app.services import incidents as svc
from app.services.audit import record_audit
from app.services.llm.groq_service import get_groq_service

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=Page[IncidentSummaryOut], dependencies=[Depends(rate_limit("reads"))])
async def list_incidents(
    params: PageParams = Depends(),
    status: IncidentStatus | None = None,
    severity: RiskLevel | None = None,
    source: DataSource | None = None,
    q: str | None = None,
    _: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> Page[IncidentSummaryOut]:
    rows, total = await svc.list_incidents(session, params, status, severity, source, q)
    return Page(
        items=[IncidentSummaryOut.model_validate(r) for r in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


@router.post("", response_model=IncidentDetail, status_code=201, dependencies=[Depends(rate_limit("writes"))])
async def create_incident(
    body: IncidentCreate,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> IncidentDetail:
    incident = await svc.create_incident(session, body, actor=principal.actor)
    return await svc.incident_detail(session, incident.id)


@router.get("/{incident_id}", response_model=IncidentDetail, dependencies=[Depends(rate_limit("reads"))])
async def get_incident(
    incident_id: uuid.UUID, _: Principal = Depends(require_principal), session: AsyncSession = Depends(get_session)
) -> IncidentDetail:
    return await svc.incident_detail(session, incident_id)


@router.patch("/{incident_id}", response_model=IncidentDetail, dependencies=[Depends(rate_limit("writes"))])
async def update_incident(
    incident_id: uuid.UUID,
    body: IncidentUpdate,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> IncidentDetail:
    await svc.update_incident(session, incident_id, body, actor=principal.actor)
    return await svc.incident_detail(session, incident_id)


@router.post(
    "/{incident_id}/notes", response_model=NoteOut, status_code=201, dependencies=[Depends(rate_limit("writes"))]
)
async def add_note(
    incident_id: uuid.UUID,
    body: NoteCreate,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> NoteOut:
    note = await svc.add_note(session, incident_id, body.body, actor=principal.actor)
    return NoteOut.model_validate(note)


@router.post("/{incident_id}/events", response_model=IncidentDetail, dependencies=[Depends(rate_limit("writes"))])
async def link_events(
    incident_id: uuid.UUID,
    body: LinkEventsRequest,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> IncidentDetail:
    await svc.link_events(session, incident_id, body.event_ids, actor=principal.actor)
    return await svc.incident_detail(session, incident_id)


@router.post(
    "/{incident_id}/ai-summary",
    response_model=AISummaryResponse,
    dependencies=[Depends(rate_limit("scans"))],
    summary="Ask the LLM to summarize the incident (stored as an AI-labelled note)",
)
async def ai_summary(
    incident_id: uuid.UUID,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> AISummaryResponse:
    incident = await svc.get_incident_or_404(session, incident_id)
    # Only structured incident metadata is sent; raw scanned messages are never stored, so never sent.
    payload = {
        "title": incident.title,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "risk_score": incident.risk_score,
        "evidence_summary": incident.evidence_summary[:2000],
        "events": [
            {
                "type": e.event_type.value,
                "severity": e.severity.value,
                "description": e.description,
                "at": e.created_at.isoformat(),
            }
            for e in incident.events[:20]
        ],
        "analyst_notes": [n.body[:500] for n in incident.notes if n.kind == NoteKind.NOTE][:5],
    }
    outcome = await get_groq_service().summarize_incident(payload)
    record_audit(
        session,
        actor=principal.actor,
        action="incident.ai_summary",
        entity_type="incident",
        entity_id=incident.id,
        details={"status": outcome.status, "model": outcome.model},
        source=incident.source,
    )
    if not outcome.ok or outcome.data is None:
        await session.commit()
        return AISummaryResponse(
            status=outcome.status,
            model=outcome.model,
            message="AI summary unavailable (" + outcome.status.replace("_", " ") + ").",
        )
    data = outcome.data
    parts = [data.summary]
    if data.key_observations:
        parts.append("Observations:\n" + "\n".join(f"- {o}" for o in data.key_observations))
    if data.next_steps:
        parts.append("Suggested next steps:\n" + "\n".join(f"- {s}" for s in data.next_steps))
    if data.limitations:
        parts.append("Limitations:\n" + "\n".join(f"- {s}" for s in data.limitations))
    await session.commit()
    note = await svc.add_note(
        session, incident.id, "\n\n".join(parts)[:4000], actor=f"AI ({outcome.model})", kind=NoteKind.AI_SUMMARY
    )
    return AISummaryResponse(
        status="ok",
        model=outcome.model,
        note=NoteOut.model_validate(note),
        message="AI summary generated by Groq and saved as an AI-labelled note.",
    )
