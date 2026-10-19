"""Pure-ASGI middleware: correlation IDs, access logging, security headers and request-size limits."""

from __future__ import annotations

import json
import logging
import re
import time
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import log_fields, request_id_ctx

logger = logging.getLogger("sentinel.http")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
    # The API only serves JSON; the interactive docs page needs its CDN assets, so CSP is scoped below.
]
API_CSP = (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'")


class RequestContextMiddleware:
    """Assigns/propagates X-Request-ID, adds security headers and logs one line per request."""

    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        incoming = dict(scope.get("headers") or []).get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        token = request_id_ctx.set(request_id)
        start = time.perf_counter()
        status_holder = {"status": 0}
        path: str = scope.get("path", "")

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode()))
                headers.extend(SECURITY_HEADERS)
                if not path.startswith(("/docs", "/redoc")):
                    headers.append(API_CSP)
                if self.hsts:
                    headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            if scope["type"] == "http":
                log_fields(
                    logger,
                    logging.INFO,
                    "request",
                    method=scope.get("method"),
                    path=path,  # path only; query strings may carry user data
                    status=status_holder["status"],
                    duration_ms=round((time.perf_counter() - start) * 1000, 1),
                )
            request_id_ctx.reset(token)


class BodySizeLimitMiddleware:
    """Rejects request bodies larger than `max_bytes`, whether or not Content-Length is declared."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send, status=400, code="bad_request", message="Invalid Content-Length")
                return

        received = 0
        too_large = False

        async def limited_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    too_large = True
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            if too_large:
                await self._reject(send)

    async def _reject(
        self,
        send: Send,
        status: int = 413,
        code: str = "payload_too_large",
        message: str = "Request body too large",
    ) -> None:
        body = json.dumps(
            {"error": {"code": code, "message": message, "request_id": request_id_ctx.get(), "details": None}}
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})


class _BodyTooLarge(Exception):
    pass
