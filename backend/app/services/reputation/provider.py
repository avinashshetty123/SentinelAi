"""URL reputation provider interface.

No provider is configured in the MVP, and SentinelAI never fabricates reputation data. A future provider
must: use a documented API, require explicit configuration, apply strict timeouts and rate limits, query
by URL/hash only (never fetch the target URL itself), and return `unavailable` on any failure.
"""

from __future__ import annotations

from typing import Protocol

from app.schemas.scan import ReputationInfo


class ReputationProvider(Protocol):
    name: str

    async def lookup(self, normalized_url: str) -> ReputationInfo: ...


class NotConfiguredProvider:
    name = "none"

    async def lookup(self, normalized_url: str) -> ReputationInfo:
        return ReputationInfo(
            status="not_configured",
            provider=None,
            note="No reputation provider is configured. Results are based only on offline URL features; "
            "the URL was not visited and its reputation is unknown.",
        )


_provider: ReputationProvider = NotConfiguredProvider()


def get_reputation_provider() -> ReputationProvider:
    return _provider
