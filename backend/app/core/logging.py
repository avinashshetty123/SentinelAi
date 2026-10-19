"""Structured logging. Request bodies and user-submitted content are never logged."""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import UTC, datetime

request_id_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        request_id = request_id_ctx.get()
        if request_id:
            payload["request_id"] = request_id
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            # Exception type only; stack traces stay in stderr formatting for development.
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # Uvicorn's access log would duplicate our own request log line.
    logging.getLogger("uvicorn.access").disabled = True
    for noisy in ("httpx", "httpcore", "groq", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def log_fields(logger: logging.Logger, level: int, msg: str, **fields: object) -> None:
    logger.log(level, msg, extra={"fields": fields})
