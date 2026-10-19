"""URL reputation: provider interface and the VirusTotal v3 implementation.

- SentinelAI never fetches the target URL itself. It only asks VirusTotal for an existing report
  (GET /api/v3/urls/{id}); it does not submit URLs for new scans.
- The API key stays server-side. Logs never contain the URL.
- Results are cached in memory (TTL) to stay within the free-tier quota (4 lookups/minute, 500/day).
- Any failure returns a non-"ok" status so the scan still completes with offline results.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import time
from datetime import UTC, datetime
from typing import Any, Protocol

import httpx

from app.schemas.scan import FlaggedEngine, ReputationInfo, ReputationStats

logger = logging.getLogger("sentinel.reputation")

CACHE_TTL_SECONDS = 1800
CACHE_MAX_ENTRIES = 500


class ReputationProvider(Protocol):
    name: str

    async def lookup(self, url: str) -> ReputationInfo: ...


class NotConfiguredProvider:
    name = "none"

    async def lookup(self, url: str) -> ReputationInfo:
        return ReputationInfo(
            status="not_configured",
            provider=None,
            note="No reputation provider is configured (set VIRUSTOTAL_API_KEY). Results use offline URL "
            "analysis only; the URL was not visited and its reputation is unknown.",
        )


class VirusTotalProvider:
    name = "virustotal"
    _BASE = "https://www.virustotal.com/api/v3/urls"

    def __init__(self, api_key: str, timeout: float = 8.0, client: httpx.AsyncClient | None = None) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._client = client
        self._cache: dict[str, tuple[float, ReputationInfo]] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()

    @staticmethod
    def report_url(url: str) -> str:
        return f"https://www.virustotal.com/gui/url/{hashlib.sha256(url.encode()).hexdigest()}"

    async def lookup(self, url: str) -> ReputationInfo:
        now = time.monotonic()
        async with self._lock:
            hit = self._cache.get(url)
            if hit and now - hit[0] < CACHE_TTL_SECONDS:
                return hit[1].model_copy(update={"cached": True})
        info = await self._fetch(url)
        if info.status == "ok":
            async with self._lock:
                if len(self._cache) >= CACHE_MAX_ENTRIES:
                    self._cache.pop(next(iter(self._cache)))
                self._cache[url] = (now, info)
        return info

    async def _fetch(self, url: str) -> ReputationInfo:
        base = {"provider": "virustotal", "report_url": self.report_url(url)}
        try:
            client = self._client or httpx.AsyncClient(timeout=self._timeout)
            try:
                resp = await client.get(f"{self._BASE}/{self.url_id(url)}", headers={"x-apikey": self._api_key})
            finally:
                if self._client is None:
                    await client.aclose()
        except httpx.TimeoutException:
            logger.warning("VirusTotal lookup timed out")
            return ReputationInfo(
                status="unavailable", note="VirusTotal lookup timed out. Offline results still apply.", **base
            )
        except httpx.HTTPError:
            logger.warning("VirusTotal lookup failed (network)")
            return ReputationInfo(
                status="unavailable", note="VirusTotal could not be reached. Offline results still apply.", **base
            )

        if resp.status_code == 404:
            return ReputationInfo(
                status="ok",
                verdict="not_found",
                **base,
                note="VirusTotal has no report for this exact URL. Unknown is not the same as safe — "
                "new phishing links are often not yet in any database.",
            )
        if resp.status_code == 429:
            logger.warning("VirusTotal quota exceeded")
            return ReputationInfo(
                status="rate_limited",
                **base,
                note="VirusTotal quota reached (free tier: 4 lookups/minute). Try again shortly.",
            )
        if resp.status_code in (401, 403):
            logger.error("VirusTotal rejected the API key")
            return ReputationInfo(
                status="unavailable", note="VirusTotal rejected the API key. Check VIRUSTOTAL_API_KEY.", **base
            )
        if resp.status_code >= 400:
            logger.warning("VirusTotal error status=%s", resp.status_code)
            return ReputationInfo(
                status="unavailable", note="VirusTotal returned an error. Offline results still apply.", **base
            )
        try:
            return self._parse(resp.json(), base)
        except (ValueError, KeyError, TypeError):
            return ReputationInfo(status="unavailable", note="VirusTotal returned an unexpected response.", **base)

    @staticmethod
    def _parse(payload: dict[str, Any], base: dict[str, Any]) -> ReputationInfo:
        attrs = payload.get("data", {}).get("attributes", {})
        raw = attrs.get("last_analysis_stats", {}) or {}
        stats = ReputationStats(
            **{k: int(raw.get(k, 0) or 0) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout")}
        )
        engines = [
            FlaggedEngine(
                engine=str(name)[:60],
                category=str(r.get("category", "")),
                result=(str(r.get("result"))[:80] if r.get("result") else None),
            )
            for name, r in (attrs.get("last_analysis_results") or {}).items()
            if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious")
        ]
        engines.sort(key=lambda e: (e.category != "malicious", e.engine.lower()))
        categories = sorted({str(c)[:60] for c in (attrs.get("categories") or {}).values()})[:8]
        last = attrs.get("last_analysis_date")
        last_at = datetime.fromtimestamp(int(last), UTC) if isinstance(last, int | float) else None

        if stats.total == 0:
            verdict, note = "unknown", "VirusTotal has a record but no engine results yet."
        elif stats.malicious > 0:
            verdict = "malicious"
            note = f"{stats.malicious} of {stats.total} security vendors flagged this URL as malicious" + (
                f" and {stats.suspicious} as suspicious." if stats.suspicious else "."
            )
        elif stats.suspicious > 0:
            verdict, note = (
                "suspicious",
                f"{stats.suspicious} of {stats.total} security vendors flagged this URL as suspicious.",
            )
        else:
            verdict = "clean"
            note = (
                f"No vendor flagged this URL ({stats.harmless} harmless, {stats.undetected} undetected). "
                "A clean report lowers concern but does not prove the link is safe."
            )
        return ReputationInfo(
            status="ok",
            verdict=verdict,
            note=note,
            stats=stats,
            flagged_engines=engines[:12],
            categories=categories,
            community_score=attrs.get("reputation"),
            last_analysis_at=last_at,
            **base,
        )


_provider: ReputationProvider = NotConfiguredProvider()


def get_reputation_provider() -> ReputationProvider:
    return _provider


def set_reputation_provider(provider: ReputationProvider) -> None:
    global _provider
    _provider = provider


def init_reputation_provider() -> None:
    """Called at startup: wires VirusTotal when VIRUSTOTAL_API_KEY is set and enabled."""
    from app.core.config import get_settings

    settings = get_settings()
    key = settings.virustotal_api_key.get_secret_value() if settings.virustotal_api_key else ""
    if settings.virustotal_enabled and key:
        set_reputation_provider(VirusTotalProvider(api_key=key, timeout=settings.virustotal_timeout_seconds))
        logger.info("Reputation provider: VirusTotal (active)")
    else:
        set_reputation_provider(NotConfiguredProvider())
        logger.info("Reputation provider: not configured")
