"""Authentication for the single-operator deployment model.

- AUTH_MODE=open: no credentials (local development / explicitly acknowledged public demo).
- AUTH_MODE=token: every protected endpoint requires `Authorization: Bearer <ADMIN_API_TOKEN>`.

Bearer tokens are sent in a header (never a cookie), so the API is not exposed to CSRF.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import Request

from app.core.config import Settings, get_settings
from app.core.errors import AppError


@dataclass(frozen=True)
class Principal:
    actor: str
    authenticated: bool


def verify_token(candidate: str | None, settings: Settings) -> bool:
    if settings.auth_mode == "open":
        return True
    expected = settings.admin_api_token.get_secret_value() if settings.admin_api_token else ""
    if not candidate or not expected:
        return False
    return hmac.compare_digest(candidate.encode(), expected.encode())


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return value.strip()


async def require_principal(request: Request) -> Principal:
    settings = get_settings()
    if settings.auth_mode == "open":
        return Principal(actor="operator", authenticated=False)
    if not verify_token(_bearer(request), settings):
        raise AppError(
            401,
            "unauthorized",
            "A valid operator token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Principal(actor="operator", authenticated=True)


async def require_demo_mode() -> None:
    if not get_settings().demo_mode_enabled:
        raise AppError(403, "demo_disabled", "Demo features are disabled on this deployment")
