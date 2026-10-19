"""In-process sliding-window rate limiter.

Suitable for a single backend instance (the documented deployment). For multiple instances, replace the
store with a shared backend such as Redis; the dependency interface stays the same.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any

from fastapi import Request

from app.core.config import get_settings
from app.core.errors import AppError


class SlidingWindowLimiter:
    def __init__(self, max_keys: int = 50_000) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()
        self._max_keys = max_keys

    async def hit(self, key: str, limit: int, window_seconds: float = 60.0) -> tuple[bool, int]:
        """Records a hit. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        async with self._lock:
            if len(self._hits) > self._max_keys:
                self._evict(now, window_seconds)
            bucket = self._hits[key]
            while bucket and bucket[0] <= now - window_seconds:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, int(bucket[0] + window_seconds - now) + 1)
                return False, retry_after
            bucket.append(now)
            return True, 0

    def _evict(self, now: float, window_seconds: float) -> None:
        stale = [k for k, b in self._hits.items() if not b or b[-1] <= now - window_seconds]
        for k in stale:
            del self._hits[k]

    def reset(self) -> None:
        self._hits.clear()


limiter = SlidingWindowLimiter()

# Called (fire-and-forget) when a client is throttled, so the dashboard can show a rate-limit event.
RateLimitHook = Callable[[str, str], Coroutine[Any, Any, None]]
_on_limited: RateLimitHook | None = None


def set_rate_limit_hook(hook: RateLimitHook | None) -> None:
    global _on_limited
    _on_limited = hook


def client_ip(request: Request) -> str:
    settings = get_settings()
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # The right-most entry is appended by the trusted proxy in front of us; left entries are
            # client-controlled and must not be trusted.
            return forwarded.split(",")[-1].strip()[:64]
    return request.client.host if request.client else "unknown"


def rate_limit(bucket: str) -> Callable[[Request], Awaitable[None]]:
    async def dependency(request: Request) -> None:
        settings = get_settings()
        if not settings.rate_limit_enabled:
            return
        limit = {
            "scans": settings.rate_limit_scans_per_minute,
            "writes": settings.rate_limit_writes_per_minute,
            "reads": settings.rate_limit_reads_per_minute,
        }.get(bucket, settings.rate_limit_reads_per_minute)
        ip = client_ip(request)
        allowed, retry_after = await limiter.hit(f"{bucket}:{ip}", limit)
        if not allowed:
            if _on_limited is not None:
                asyncio.create_task(_on_limited(bucket, ip))  # noqa: RUF006 - fire and forget
            raise AppError(
                429,
                "rate_limited",
                "Too many requests. Please slow down and retry later.",
                details={"retry_after_seconds": retry_after},
                headers={"Retry-After": str(retry_after)},
            )

    return dependency
