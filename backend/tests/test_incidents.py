from __future__ import annotations


async def _new_incident(client, **extra) -> dict:
    payload = {"title": "Phishing campaign", "severity": "HIGH", "description": "Reported by staff", **extra}
    r = await client.post("/api/v1/incidents", json=payload)
    assert r.status_code == 201, r.text
    return r.json()


async def test_incident_lifecycle_with_audit_trail(client) -> None:
    incident = await _new_incident(client)
    iid = incident["id"]
    assert incident["status"] == "OPEN"

    r = await client.patch(f"/api/v1/incidents/{iid}", json={"status": "INVESTIGATING"})
    assert r.json()["status"] == "INVESTIGATING"

    note = await client.post(f"/api/v1/incidents/{iid}/notes", json={"body": "Blocked sender domain."})
    assert note.status_code == 201

    # Resolving requires resolution notes.
    r = await client.patch(f"/api/v1/incidents/{iid}", json={"status": "RESOLVED"})
    assert r.status_code == 422
    r = await client.patch(f"/api/v1/incidents/{iid}", json={"status": "RESOLVED",
                                                             "resolution_notes": "Users warned; domain blocked."})
    detail = r.json()
    assert detail["status"] == "RESOLVED" and detail["resolved_at"]

    actions = [a["action"] for a in detail["audit"]]
    assert actions == ["incident.created", "incident.updated", "incident.note_added", "incident.updated"]
    kinds = [t["kind"] for t in detail["timeline"]]
    assert kinds[0] == "created" and "note" in kinds and kinds.count("status_change") == 2
    # A resolution event was emitted and linked to the incident.
    events = (await client.get("/api/v1/events", params={"event_type": "incident_resolved"})).json()
    assert events["total"] == 1 and events["items"][0]["incident_id"] == iid


async def test_reopen_clears_resolved_at(client) -> None:
    iid = (await _new_incident(client))["id"]
    await client.patch(f"/api/v1/incidents/{iid}", json={"status": "FALSE_POSITIVE", "resolution_notes": "Benign"})
    r = await client.patch(f"/api/v1/incidents/{iid}", json={"status": "INVESTIGATING"})
    assert r.json()["resolved_at"] is None


async def test_link_events_and_conflict(client) -> None:
    ev = (await client.post("/api/v1/demo/events", json={"event_type": "suspicious_login"})).json()
    a = (await _new_incident(client))["id"]
    b = (await _new_incident(client, title="Second incident"))["id"]
    r = await client.post(f"/api/v1/incidents/{a}/events", json={"event_ids": [ev["id"]]})
    assert r.status_code == 200 and r.json()["events"][0]["id"] == ev["id"]
    assert (await client.post(f"/api/v1/incidents/{b}/events", json={"event_ids": [ev["id"]]})).status_code == 409
    missing = "00000000-0000-0000-0000-000000000001"
    assert (await client.post(f"/api/v1/incidents/{a}/events", json={"event_ids": [missing]})).status_code == 422


async def test_filters_and_pagination(client) -> None:
    for i in range(3):
        await _new_incident(client, title=f"Incident {i}", severity="CRITICAL" if i == 0 else "LOW")
    page = (await client.get("/api/v1/incidents", params={"page_size": 2})).json()
    assert page["total"] == 3 and len(page["items"]) == 2
    crit = (await client.get("/api/v1/incidents", params={"severity": "CRITICAL"})).json()
    assert crit["total"] == 1
    search = (await client.get("/api/v1/incidents", params={"q": "Incident 2"})).json()
    assert search["total"] == 1


async def test_unknown_incident_404_and_invalid_payloads(client) -> None:
    assert (await client.get("/api/v1/incidents/00000000-0000-0000-0000-000000000009")).status_code == 404
    assert (await client.post("/api/v1/incidents", json={"title": "x", "severity": "HIGH"})).status_code == 422
    iid = (await _new_incident(client))["id"]
    assert (await client.patch(f"/api/v1/incidents/{iid}", json={})).status_code == 422
    assert (await client.patch(f"/api/v1/incidents/{iid}", json={"status": "DONE"})).status_code == 422


async def test_ai_summary_saved_as_labelled_note(client, fake_llm) -> None:
    iid = (await _new_incident(client))["id"]
    fake = fake_llm()
    r = (await client.post(f"/api/v1/incidents/{iid}/ai-summary")).json()
    assert r["status"] == "ok" and r["note"]["kind"] == "ai_summary"
    assert r["note"]["author"].startswith("AI (")
    assert fake.calls[0]["incident"]["title"] == "Phishing campaign"


async def test_ai_summary_unavailable_is_reported(client) -> None:
    iid = (await _new_incident(client))["id"]
    r = (await client.post(f"/api/v1/incidents/{iid}/ai-summary")).json()
    assert r["status"] == "disabled" and r["note"] is None
