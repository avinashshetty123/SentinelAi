"""In-process WebSocket broadcast hub.

Flow: application action → validated event → DB commit → broadcast() → connected dashboards.
Single-process by design (one Uvicorn worker). For multiple workers, put Redis Pub/Sub behind broadcast().
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections import deque
from datetime import UTC, datetime
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("sentinel.ws")

MAX_CLIENTS = 200
SEND_TIMEOUT_SECONDS = 2.0


class ConnectionManager:
    def __init__(self, history_size: int = 100) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self.recent: deque[dict[str, Any]] = deque(maxlen=history_size)  # bounded in-memory history

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def register(self, websocket: WebSocket) -> bool:
        async with self._lock:
            if len(self._clients) >= MAX_CLIENTS:
                return False
            self._clients.add(websocket)
            return True

    async def unregister(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(websocket)

    async def broadcast(self, message_type: str, data: Any) -> None:
        envelope = {"type": message_type, "at": datetime.now(UTC).isoformat(), "data": data}
        self.recent.append(envelope)
        payload = json.dumps(envelope, default=str)
        async with self._lock:
            clients = list(self._clients)
        if not clients:
            return
        results = await asyncio.gather(*(self._send(ws, payload) for ws in clients), return_exceptions=True)
        dead = [ws for ws, ok in zip(clients, results, strict=True) if ok is not True]
        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.discard(ws)
            for ws in dead:
                with contextlib.suppress(Exception):
                    await ws.close()

    @staticmethod
    async def _send(ws: WebSocket, payload: str) -> bool:
        try:
            await asyncio.wait_for(ws.send_text(payload), timeout=SEND_TIMEOUT_SECONDS)
            return True
        except Exception:
            return False


manager = ConnectionManager()
