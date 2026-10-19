from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError
from app.core.ratelimit import rate_limit
from app.core.security import Principal, require_demo_mode, require_principal
from app.database.session import get_session
from app.schemas.event import EventOut, SimulatedEventRequest
from app.schemas.system import (
    DemoRunOut,
    DemoStatus,
    ResetResult,
    ScenarioOut,
    SimulatorStart,
    SimulatorStatus,
)
from app.services.demo import runner
from app.services.demo.scenarios import SCENARIOS

router = APIRouter(prefix="/demo", tags=["demo"], dependencies=[Depends(require_demo_mode)])


@router.get("/scenarios", response_model=list[ScenarioOut])
async def list_scenarios(_: Principal = Depends(require_principal)) -> list[ScenarioOut]:
    return [
        ScenarioOut(
            id=s.id,
            title=s.title,
            description=s.description,
            steps=[st.title for st in s.steps],
            expected_outcome=s.expected_outcome,
        )
        for s in SCENARIOS.values()
    ]


@router.post(
    "/scenarios/{scenario_id}/run",
    response_model=DemoRunOut,
    status_code=202,
    dependencies=[Depends(rate_limit("writes"))],
)
async def run_scenario(
    scenario_id: str, _: Principal = Depends(require_principal), session: AsyncSession = Depends(get_session)
) -> DemoRunOut:
    run = await runner.start_scenario(session, scenario_id)
    return runner.run_to_out(run)


@router.get("/scenarios/{scenario_id}/status", response_model=DemoStatus)
async def scenario_status(
    scenario_id: str, _: Principal = Depends(require_principal), session: AsyncSession = Depends(get_session)
) -> DemoStatus:
    run = await runner.latest_run(session, scenario_id)
    return DemoStatus(scenario_id=scenario_id, run=runner.run_to_out(run) if run else None)


@router.post("/runs/{run_id}/cancel", status_code=202, dependencies=[Depends(rate_limit("writes"))])
async def cancel_run(run_id: uuid.UUID, _: Principal = Depends(require_principal)) -> dict[str, bool]:
    if not await runner.cancel_run(run_id):
        raise ConflictError("That run is not currently running")
    return {"cancelled": True}


@router.post("/events", response_model=EventOut, status_code=201, dependencies=[Depends(rate_limit("writes"))])
async def simulate_event(
    body: SimulatedEventRequest, _: Principal = Depends(require_principal), session: AsyncSession = Depends(get_session)
) -> EventOut:
    event = await runner.generate_simulated_event(session, body.event_type)
    return EventOut.model_validate(event)


@router.get("/simulator", response_model=SimulatorStatus)
async def simulator_status(_: Principal = Depends(require_principal)) -> SimulatorStatus:
    return runner.simulator.status()


@router.post("/simulator/start", response_model=SimulatorStatus, dependencies=[Depends(rate_limit("writes"))])
async def simulator_start(body: SimulatorStart, _: Principal = Depends(require_principal)) -> SimulatorStatus:
    return await runner.simulator.start(body.interval_seconds)


@router.post("/simulator/stop", response_model=SimulatorStatus)
async def simulator_stop(_: Principal = Depends(require_principal)) -> SimulatorStatus:
    return await runner.simulator.stop()


@router.post(
    "/reset",
    response_model=ResetResult,
    dependencies=[Depends(rate_limit("writes"))],
    summary="Delete ONLY demo/simulation records (never application data)",
)
async def reset(
    principal: Principal = Depends(require_principal), session: AsyncSession = Depends(get_session)
) -> ResetResult:
    counts = await runner.reset_demo_data(session, actor=principal.actor)
    return ResetResult(deleted=counts, message="Demo and simulation records removed. Application data untouched.")
