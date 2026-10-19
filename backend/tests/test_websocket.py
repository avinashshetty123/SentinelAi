"""WebSocket integration: a persisted event is broadcast to connected clients.

Uses Starlette's TestClient (its own event loop + full app lifespan) against the same SQLite test database.
These are synchronous tests on purpose.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.core.config import get_settings
from app.main import create_app


def _receive_until(ws, message_type: str, limit: int = 20) -> dict:
    for _ in range(limit):
        message = ws.receive_json()
        if message["type"] == message_type:
            return message
    raise AssertionError(f"no {message_type} message received")


def test_event_broadcast_reaches_client() -> None:
    with TestClient(create_app()) as client:
        with client.websocket_connect("/api/v1/ws/events", headers={"origin": "http://localhost:3000"}) as ws:
            assert ws.receive_json()["type"] == "hello"
            r = client.post("/api/v1/demo/events", json={"event_type": "failed_login_burst"})
            assert r.status_code == 201
            message = _receive_until(ws, "event.created")
            assert message["data"]["id"] == r.json()["id"]
            assert message["data"]["source"] == "simulation"
            # The broadcast event is the persisted one.
            assert client.get(f"/api/v1/events/{message['data']['id']}").status_code == 200


def test_scan_triggers_broadcast() -> None:
    with TestClient(create_app()) as client:
        with client.websocket_connect("/api/v1/ws/events", headers={"origin": "http://localhost:3000"}) as ws:
            ws.receive_json()
            client.post("/api/v1/scans/message", json={
                "text": "URGENT: your account will be suspended. Share the OTP and verify at http://paypa1.com"})
            assert _receive_until(ws, "scan.created")["data"]["risk_level"] in ("HIGH", "CRITICAL")
            assert _receive_until(ws, "event.created")["data"]["event_type"] == "high_risk_message"


def test_foreign_origin_rejected() -> None:
    with TestClient(create_app()) as client:
        with pytest.raises(WebSocketDisconnect), client.websocket_connect(
                "/api/v1/ws/events", headers={"origin": "https://evil.example"}) as ws:
            ws.receive_json()


def test_token_mode_requires_auth_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "x" * 32
    monkeypatch.setenv("AUTH_MODE", "token")
    monkeypatch.setenv("ADMIN_API_TOKEN", token)
    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as client:
            with pytest.raises(WebSocketDisconnect), client.websocket_connect("/api/v1/ws/events") as ws:
                ws.send_json({"type": "auth", "token": "wrong"})
                ws.receive_json()
            with client.websocket_connect("/api/v1/ws/events") as ws:
                ws.send_json({"type": "auth", "token": token})
                assert ws.receive_json()["type"] == "hello"
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()
