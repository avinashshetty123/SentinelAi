"""WebSocket endpoint for live security events.

Protocol (JSON text frames):
  server → client: {"type": "hello" | "event.created" | "event.updated" | "incident.created" | "incident.updated"
                    | "scan.created" | "demo.progress" | "demo.reset" | "simulator.status" | "ping", "at", "data"}
  client → server: {"type": "auth", "token": "..."} (first frame, only when AUTH_MODE=token) or {"type": "pong"}
The token is sent in a frame rather than the URL so it does not appear in access logs.
"""

from __future__ import annotations

import asyncio
import contextlib
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.config import get_settings
from app.core.security import verify_token
from app.websocket.manager import manager

router = APIRouter()

PING_INTERVAL_SECONDS = 25
AUTH_TIMEOUT_SECONDS = 5
MAX_CLIENT_FRAME = 2048


def _origin_allowed(origin: str | None) -> bool:
    import re

    settings = get_settings()
    if origin is None:
        return True  # non-browser clients
    origin = origin.rstrip("/")
    if origin in settings.cors_origin_list:
        return True
    return bool(settings.cors_origin_regex and re.fullmatch(settings.cors_origin_regex, origin))


@router.websocket("/ws/events")
async def events_socket(websocket: WebSocket) -> None:
    settings = get_settings()
    # Browsers do not apply CORS to WebSockets, so validate Origin explicitly (prevents cross-site hijacking).
    if not _origin_allowed(websocket.headers.get("origin")):
        await websocket.close(code=1008)
        return
    await websocket.accept()

    if settings.auth_mode == "token":
        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=AUTH_TIMEOUT_SECONDS)
            message = json.loads(raw[:MAX_CLIENT_FRAME])
            ok = message.get("type") == "auth" and verify_token(str(message.get("token", "")), settings)
        except (TimeoutError, json.JSONDecodeError, AttributeError, WebSocketDisconnect):
            ok = False
        if not ok:
            with contextlib.suppress(Exception):
                await websocket.close(code=4401)
            return

    if not await manager.register(websocket):
        await websocket.close(code=1013)  # try again later
        return
    try:
        await websocket.send_json({"type": "hello", "data": {"clients": manager.client_count}})

        async def pinger() -> None:
            while True:
                await asyncio.sleep(PING_INTERVAL_SECONDS)
                await websocket.send_json({"type": "ping"})

        ping_task = asyncio.create_task(pinger())
        try:
            while True:
                raw = await websocket.receive_text()
                if len(raw) > MAX_CLIENT_FRAME:
                    break  # clients only send tiny control frames
        finally:
            ping_task.cancel()
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await manager.unregister(websocket)
