from __future__ import annotations

import asyncio

from sqlalchemy import func, select

from app.models import Incident, Scan, SecurityEvent
from app.models.enums import DataSource


async def _wait_for_run(client, scenario_id: str, timeout: float = 10.0) -> dict:
    for _ in range(int(timeout / 0.05)):
        status = (await client.get(f"/api/v1/demo/scenarios/{scenario_id}/status")).json()
        if status["run"] and status["run"]["status"] != "running":
            return status["run"]
        await asyncio.sleep(0.05)
    raise AssertionError("demo run did not finish")


async def test_list_scenarios(client) -> None:
    scenarios = (await client.get("/api/v1/demo/scenarios")).json()
    assert {s["id"] for s in scenarios} == {"payment-scam", "job-offer-scam", "account-takeover"}


async def test_payment_scenario_uses_real_pipeline(client, session) -> None:
    r = await client.post("/api/v1/demo/scenarios/payment-scam/run")
    assert r.status_code == 202
    run = await _wait_for_run(client, "payment-scam")
    assert run["status"] == "completed", run
    assert all(s["status"] == "completed" for s in run["steps"])
    incident_id = run["steps"][2]["refs"]["incident_id"]

    detail = (await client.get(f"/api/v1/incidents/{incident_id}")).json()
    assert detail["source"] == "demo" and detail["title"].startswith("[DEMO]")
    assert detail["severity"] in ("HIGH", "CRITICAL")
    assert len(detail["events"]) >= 2  # message + URL high-risk events linked
    assert any(n["author"] == "demo-analyst" for n in detail["notes"])
    scans = (await session.scalars(select(Scan))).all()
    assert len(scans) == 2 and all(s.source == DataSource.DEMO for s in scans)
    assert all(s.risk_level.value in ("HIGH", "CRITICAL") for s in scans)


async def test_account_takeover_scenario(client) -> None:
    await client.post("/api/v1/demo/scenarios/account-takeover/run")
    run = await _wait_for_run(client, "account-takeover")
    assert run["status"] == "completed"
    incident_id = run["steps"][-1]["refs"]["incident_id"]
    detail = (await client.get(f"/api/v1/incidents/{incident_id}")).json()
    types = {e["event_type"] for e in detail["events"]}
    assert {"failed_login_burst", "suspicious_login", "account_takeover_warning"} <= types
    assert detail["severity"] == "CRITICAL"


async def test_concurrent_run_rejected(client, settings_env) -> None:
    settings_env(DEMO_STEP_DELAY_SECONDS="0.3")
    assert (await client.post("/api/v1/demo/scenarios/job-offer-scam/run")).status_code == 202
    assert (await client.post("/api/v1/demo/scenarios/payment-scam/run")).status_code == 409
    run = (await client.get("/api/v1/demo/scenarios/job-offer-scam/status")).json()["run"]
    assert (await client.post(f"/api/v1/demo/runs/{run['id']}/cancel")).status_code == 202
    final = await _wait_for_run(client, "job-offer-scam")
    assert final["status"] == "cancelled"


async def test_unknown_scenario_404(client) -> None:
    assert (await client.post("/api/v1/demo/scenarios/nope/run")).status_code == 404


async def test_reset_removes_only_demo_data(client, session) -> None:
    # Application data
    app_scan = (await client.post("/api/v1/scans/message", json={
        "text": "URGENT: share the OTP now or your account will be suspended. Verify at http://paypa1.com"})).json()
    app_incident = (await client.post("/api/v1/incidents", json={"title": "Real incident", "severity": "LOW"})).json()
    # Demo + simulation data
    await client.post("/api/v1/demo/scenarios/payment-scam/run")
    await _wait_for_run(client, "payment-scam")
    await client.post("/api/v1/demo/events", json={"event_type": "failed_login_burst"})

    r = await client.post("/api/v1/demo/reset")
    assert r.status_code == 200
    deleted = r.json()["deleted"]
    assert deleted["scans"] == 2 and deleted["incidents"] == 1 and deleted["events"] >= 3

    assert (await client.get(f"/api/v1/scans/{app_scan['id']}")).status_code == 200
    assert (await client.get(f"/api/v1/incidents/{app_incident['id']}")).status_code == 200
    remaining_sources = set((await session.scalars(select(SecurityEvent.source))).all())
    assert remaining_sources <= {DataSource.APPLICATION}
    assert await session.scalar(select(func.count()).select_from(Incident)) >= 1


async def test_simulated_event_and_simulator_single_instance(client) -> None:
    ev = (await client.post("/api/v1/demo/events", json={"event_type": "suspicious_login"})).json()
    assert ev["source"] == "simulation" and ev["description"].startswith("[SIMULATED]")
    assert (await client.post("/api/v1/demo/events", json={"event_type": "incident_created"})).status_code == 422

    started = await client.post("/api/v1/demo/simulator/start", json={"interval_seconds": 1})
    assert started.status_code == 200 and started.json()["running"] is True
    assert (await client.post("/api/v1/demo/simulator/start", json={"interval_seconds": 1})).status_code == 409
    for _ in range(40):  # first synthetic event is generated immediately by the background task
        if (await client.get("/api/v1/demo/simulator")).json()["events_generated"] >= 1:
            break
        await asyncio.sleep(0.05)
    stopped = (await client.post("/api/v1/demo/simulator/stop")).json()
    assert stopped["running"] is False and stopped["events_generated"] >= 1
