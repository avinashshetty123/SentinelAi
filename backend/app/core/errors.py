"""Consistent error envelope: {"error": {"code", "message", "request_id", "details"}}.

Internal exception details and stack traces are never returned to clients.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import request_id_ctx

logger = logging.getLogger("sentinel.errors")


class AppError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers


class NotFoundError(AppError):
    def __init__(self, entity: str) -> None:
        super().__init__(404, "not_found", f"{entity} not found")


class ConflictError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(409, "conflict", message)


def _envelope(status_code: int, code: str, message: str, details: Any = None, headers=None) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id_ctx.get(),
                "details": details,
            }
        },
        headers=headers,
    )


_STATUS_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    422: "validation_error",
    429: "rate_limited",
}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return _envelope(exc.status_code, exc.code, exc.message, exc.details, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Strip the submitted "input" values so user content is not echoed back in errors.
        details = [
            {"loc": list(err.get("loc", [])), "msg": err.get("msg"), "type": err.get("type")} for err in exc.errors()
        ]
        return _envelope(422, "validation_error", "Request validation failed", details)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _STATUS_CODES.get(exc.status_code, "http_error")
        message = exc.detail if isinstance(exc.detail, str) else code.replace("_", " ")
        return _envelope(exc.status_code, code, message, headers=getattr(exc, "headers", None))

    @app.exception_handler(HTTPException)
    async def _fastapi_http(request: Request, exc: HTTPException) -> JSONResponse:
        return await _http(request, exc)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled exception", exc_info=exc)
        return _envelope(500, "internal_error", "An unexpected error occurred")
