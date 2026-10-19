"""Executes demo scenarios through the real analysis, event and incident services, plus a bounded
synthetic event simulator and a demo-only reset."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AppError, ConflictError, NotFoundError
from app.database.base import utcnow
from app.database.session import get_sessionmaker
from app.models import AuditLog, DemoRun, Incident, Scan, SecurityEvent
from app.models.enums import DataSource, DemoRunStatus, EventType, NoteKind, RiskLevel
from app.schemas.event import EventCreate
from app.schemas.incident import IncidentCreate
from app.schemas.scan import MessageScanRequest, UrlScanRequest
from app.schemas.system import DemoRunOut, DemoStep, SimulatorStatus
from app.services.analysis import AnalysisContext, analyze_message, analyze_url_scan
from app.services.audit import record_audit
from app.services.demo.scenarios import SCENARIOS, Scenario, ScenarioStep
from app.services.events.service import create_event
from app.services.incidents import add_note, create_incident
from app.websocket.manager import manager

logger = logging.getLogger("sentinel.demo")

_run_lock = asyncio.Lock()
_active_task: asyncio.Task[None] | None = None
_active_run_id: uuid.UUID | None = None


def run_to_out(run: DemoRun) -> DemoRunOut:
    return DemoRunOut(
        id=run.id,
        scenario_id=run.scenario_id,
        status=run.status.value,
        steps=[DemoStep(**s) for s in run.steps],
        started_at=run.started_at,
        finished_at=run.finished_at,
        error=run.error,
    )


async def _save_progress(session: AsyncSession, run: DemoRun, steps: list[dict[str, Any]]) -> None:
    run.steps = [dict(s) for s in steps]  # new list so the JSON column is marked dirty
    await session.commit()
    await manager.broadcast("demo.progress", run_to_out(run).model_dump(mode="json"))


async def _execute_step(
    session: AsyncSession,
    scenario: Scenario,
    step: ScenarioStep,
    run: DemoRun,
    ctx: AnalysisContext,
    state: dict[str, Any],
) -> tuple[str, dict[str, str]]:
    if step.kind == "message_scan":
        result = await analyze_message(
            session, MessageScanRequest(text=step.text, content_type=step.content_type, use_llm=True), ctx
        )
        state.setdefault("scan_ids", []).append(result.id)
        state["top_scan"] = state.get("top_scan") or result
        if result.related_event_id:
            state.setdefault("event_ids", []).append(result.related_event_id)
        refs = {"scan_id": str(result.id)}
        if result.related_event_id:
            refs["event_id"] = str(result.related_event_id)
        ai = "AI explanation included" if result.llm.used else f"AI explanation unavailable ({result.llm.status})"
        return f"{result.risk_level.value} · score {result.risk_score}/100 · {ai}", refs
    if step.kind == "url_scan":
        result = await analyze_url_scan(session, UrlScanRequest(url=step.url, use_llm=False), ctx)
        state.setdefault("scan_ids", []).append(result.id)
        if result.related_event_id:
            state.setdefault("event_ids", []).append(result.related_event_id)
        refs = {"scan_id": str(result.id)}
        if result.related_event_id:
            refs["event_id"] = str(result.related_event_id)
        return f"{result.risk_level.value} · score {result.risk_score}/100 · {len(result.findings)} findings", refs
    if step.kind == "sim_event":
        assert step.event_type is not None
        event = await create_event(
            session,
            EventCreate(
                event_type=step.event_type,
                severity=step.severity,
                actor=step.actor,
                description=step.description,
                source=DataSource.DEMO,
                demo_run_id=run.id,
                details={"scenario": scenario.id, "synthetic": True},
            ),
        )
        state.setdefault("event_ids", []).append(event.id)
        return f"{step.event_type.value} event broadcast", {"event_id": str(event.id)}
    if step.kind == "create_incident":
        top = state.get("top_scan")
        severities = [RiskLevel.HIGH]
        if top is not None:
            severities.append(top.risk_level)
        events = (
            await session.scalars(select(SecurityEvent).where(SecurityEvent.id.in_(state.get("event_ids", []))))
        ).all()
        severities.extend(e.severity for e in events)
        severity = max(severities, key=lambda s: s.rank)
        evidence = []
        if top is not None:
            evidence.append(f"Message scan {top.id}: {top.risk_level.value} ({top.risk_score}/100)")
            evidence.extend(f"- {f.title} (+{f.points:g})" for f in top.findings if f.points > 0)
        evidence.extend(f"Event: {e.description}" for e in events if e.scan_id is None)
        incident = await create_incident(
            session,
            IncidentCreate(
                title=scenario.incident_title,
                severity=severity,
                risk_score=top.risk_score if top is not None else None,
                description=f"Opened by demo scenario '{scenario.title}'. All data is synthetic.",
                evidence_summary="\n".join(evidence)[:4000],
                scan_id=top.id if top is not None else None,
                event_ids=state.get("event_ids", []),
            ),
            actor="demo-scenario",
            source=DataSource.DEMO,
            demo_run_id=run.id,
        )
        state["incident_id"] = incident.id
        return f"Incident opened ({severity.value}) with {len(events)} linked events", {"incident_id": str(incident.id)}
    if step.kind == "note":
        incident_id = state.get("incident_id")
        if incident_id is None:
            return "skipped (no incident)", {}
        await add_note(session, incident_id, step.description, actor="demo-analyst", kind=NoteKind.NOTE)
        return "Triage note added", {"incident_id": str(incident_id)}
    raise ValueError(f"unknown step kind {step.kind}")


async def _run_scenario(run_id: uuid.UUID, scenario: Scenario) -> None:
    global _active_task, _active_run_id
    settings = get_settings()
    async with get_sessionmaker()() as session:
        run = await session.get(DemoRun, run_id)
        assert run is not None
        steps = [dict(s) for s in run.steps]
        ctx = AnalysisContext(source=DataSource.DEMO, demo_run_id=run.id, actor="demo-scenario", auto_incident=False)
        state: dict[str, Any] = {}
        try:
            for index, step in enumerate(scenario.steps):
                steps[index].update(status="running", at=datetime.now(UTC).isoformat())
                await _save_progress(session, run, steps)
                await asyncio.sleep(settings.demo_step_delay_seconds)
                detail, refs = await _execute_step(session, scenario, step, run, ctx, state)
                steps[index].update(status="completed", detail=detail, refs=refs, at=datetime.now(UTC).isoformat())
                await _save_progress(session, run, steps)
            run.status = DemoRunStatus.COMPLETED
        except asyncio.CancelledError:
            await session.rollback()
            for s in steps:
                if s["status"] in ("pending", "running"):
                    s["status"] = "skipped"
            run.status = DemoRunStatus.CANCELLED
            run.error = "Cancelled by operator"
        except Exception as exc:
            logger.exception("Demo scenario failed")
            await session.rollback()
            for s in steps:
                if s["status"] == "running":
                    s["status"] = "failed"
            run.status = DemoRunStatus.FAILED
            run.error = type(exc).__name__
        finally:
            run.finished_at = utcnow()
            run.steps = [dict(s) for s in steps]
            with contextlib.suppress(Exception):
                await session.commit()
                await manager.broadcast("demo.progress", run_to_out(run).model_dump(mode="json"))
            _active_task = None
            _active_run_id = None


async def start_scenario(session: AsyncSession, scenario_id: str) -> DemoRun:
    global _active_task, _active_run_id
    scenario = SCENARIOS.get(scenario_id)
    if scenario is None:
        raise NotFoundError("Scenario")
    async with _run_lock:
        if _active_task is not None and not _active_task.done():
            raise ConflictError("Another demo scenario is already running")
        run = DemoRun(
            scenario_id=scenario_id,
            status=DemoRunStatus.RUNNING,
            steps=[
                {"index": i, "title": s.title, "status": "pending", "detail": None, "refs": {}, "at": None}
                for i, s in enumerate(scenario.steps)
            ],
        )
        session.add(run)
        record_audit(
            session,
            actor="operator",
            action="demo.scenario_started",
            entity_type="demo_run",
            entity_id=run.id,
            details={"scenario_id": scenario_id},
            source=DataSource.DEMO,
        )
        await session.commit()
        await session.refresh(run)
        _active_run_id = run.id
        _active_task = asyncio.create_task(_run_scenario(run.id, scenario))
    return run


async def cancel_run(run_id: uuid.UUID) -> bool:
    if _active_task is None or _active_run_id != run_id or _active_task.done():
        return False
    _active_task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await asyncio.wait_for(asyncio.shield(_active_task), timeout=5)
    return True


async def latest_run(session: AsyncSession, scenario_id: str) -> DemoRun | None:
    if scenario_id not in SCENARIOS:
        raise NotFoundError("Scenario")
    return await session.scalar(
        select(DemoRun).where(DemoRun.scenario_id == scenario_id).order_by(DemoRun.started_at.desc()).limit(1)
    )


# ---------------------------------------------------------------------------------------------------------
# Synthetic event generation
# ---------------------------------------------------------------------------------------------------------
_SIMULATED_TEMPLATES: dict[EventType, tuple[RiskLevel, str]] = {
    EventType.FAILED_LOGIN_BURST: (
        RiskLevel.MEDIUM,
        "[SIMULATED] {n} failed sign-in attempts in 2 minutes for {actor}.",
    ),
    EventType.SUSPICIOUS_LOGIN: (
        RiskLevel.HIGH,
        "[SIMULATED] Sign-in for {actor} from an unrecognized device and location.",
    ),
    EventType.ACCOUNT_TAKEOVER_WARNING: (
        RiskLevel.CRITICAL,
        "[SIMULATED] Possible account takeover for {actor}: password and recovery e-mail changed within minutes.",
    ),
    EventType.RATE_LIMIT: (RiskLevel.MEDIUM, "[SIMULATED] Burst of {n} API requests from {actor} throttled."),
    EventType.HIGH_RISK_MESSAGE: (RiskLevel.HIGH, "[SIMULATED] High-risk message reported by {actor}."),
    EventType.HIGH_RISK_URL: (RiskLevel.HIGH, "[SIMULATED] High-risk link reported by {actor}."),
}


async def generate_simulated_event(session: AsyncSession, event_type: EventType) -> SecurityEvent:
    template = _SIMULATED_TEMPLATES.get(event_type)
    if template is None:
        raise AppError(422, "validation_error", "This event type cannot be simulated directly")
    severity, text = template
    actor = f"synthetic-user-{random.randint(1, 40):03d}"
    return await create_event(
        session,
        EventCreate(
            event_type=event_type,
            severity=severity,
            actor=actor,
            description=text.format(actor=actor, n=random.randint(6, 30)),
            source=DataSource.SIMULATION,
            details={"synthetic": True},
        ),
    )


class Simulator:
    """Background generator of synthetic events. Only one instance runs at a time; auto-stops."""

    def __init__(self) -> None:
        self._task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()
        self.started_at: datetime | None = None
        self.interval: float | None = None
        self.count = 0

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def status(self) -> SimulatorStatus:
        return SimulatorStatus(
            running=self.running,
            started_at=self.started_at if self.running else None,
            interval_seconds=self.interval if self.running else None,
            events_generated=self.count,
            max_seconds=get_settings().demo_simulator_max_seconds,
        )

    async def start(self, interval: float) -> SimulatorStatus:
        async with self._lock:
            if self.running:
                raise ConflictError("The event simulator is already running")
            self.started_at = utcnow()
            self.interval = interval
            self.count = 0
            self._task = asyncio.create_task(self._loop(interval))
        await manager.broadcast("simulator.status", self.status().model_dump(mode="json"))
        return self.status()

    async def stop(self) -> SimulatorStatus:
        async with self._lock:
            task, self._task = self._task, None
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        await manager.broadcast("simulator.status", self.status().model_dump(mode="json"))
        return self.status()

    async def _loop(self, interval: float) -> None:
        deadline = asyncio.get_running_loop().time() + get_settings().demo_simulator_max_seconds
        types = (
            [EventType.FAILED_LOGIN_BURST] * 4
            + [EventType.SUSPICIOUS_LOGIN] * 2
            + [EventType.RATE_LIMIT, EventType.ACCOUNT_TAKEOVER_WARNING]
        )
        try:
            while asyncio.get_running_loop().time() < deadline:
                async with get_sessionmaker()() as session:
                    await generate_simulated_event(session, random.choice(types))
                self.count += 1
                await asyncio.sleep(interval)
        finally:
            self._task = None
            await manager.broadcast("simulator.status", self.status().model_dump(mode="json"))


simulator = Simulator()


# ---------------------------------------------------------------------------------------------------------
# Demo reset: only rows with demo/simulation provenance are removed.
# ---------------------------------------------------------------------------------------------------------
async def reset_demo_data(session: AsyncSession, actor: str) -> dict[str, int]:
    if _active_task is not None and not _active_task.done():
        raise ConflictError("Stop the running demo scenario before resetting")
    if simulator.running:
        await simulator.stop()
    demo_sources = (DataSource.DEMO, DataSource.SIMULATION)
    demo_incident_ids = (await session.scalars(select(Incident.id).where(Incident.source.in_(demo_sources)))).all()

    counts: dict[str, int] = {}
    # Unlink application events from demo incidents (should not happen, but never delete real events).
    res = await session.execute(delete(SecurityEvent).where(SecurityEvent.source.in_(demo_sources)))
    counts["events"] = res.rowcount or 0  # type: ignore[attr-defined]
    if demo_incident_ids:
        res = await session.execute(
            delete(AuditLog).where(AuditLog.entity_type == "incident", AuditLog.entity_id.in_(demo_incident_ids))
        )
        counts["incident_audit_logs"] = res.rowcount or 0  # type: ignore[attr-defined]
    res = await session.execute(delete(Incident).where(Incident.source.in_(demo_sources)))
    counts["incidents"] = res.rowcount or 0  # type: ignore[attr-defined]
    res = await session.execute(delete(Scan).where(Scan.source.in_(demo_sources)))
    counts["scans"] = res.rowcount or 0  # type: ignore[attr-defined]
    res = await session.execute(delete(AuditLog).where(AuditLog.source.in_(demo_sources)))
    counts["demo_audit_logs"] = res.rowcount or 0  # type: ignore[attr-defined]
    res = await session.execute(delete(DemoRun))
    counts["demo_runs"] = res.rowcount or 0  # type: ignore[attr-defined]
    record_audit(
        session,
        actor=actor,
        action="demo.reset",
        entity_type="system",
        entity_id=None,
        details=counts,
        source=DataSource.APPLICATION,
    )
    await session.commit()
    await manager.broadcast("demo.reset", counts)
    return counts
