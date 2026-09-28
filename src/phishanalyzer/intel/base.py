"""Shared plumbing for threat-intel clients: errors, rate limits, caching, HTTP."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from datetime import date
from typing import Any, Protocol

import httpx


class IntelUnavailable(Exception):
    """A lookup could not be made (network error, quota exhausted, bad key...).

    The analyzer turns this into an `unavailable` finding: the verdict is marked partial
    and re-checked later instead of failing.
    """


class RateLimiter:
    """Spaces requests to stay under a service's per-minute and per-day quotas.

    Waits at most `max_wait` seconds for a slot; if the next slot is further away the
    lookup is reported unavailable rather than stalling the whole scan.
    """

    def __init__(
        self,
        per_minute: float | None = None,
        per_day: int | None = None,
        max_wait: float = 20.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.interval = 60.0 / per_minute if per_minute else 0.0
        self.per_day = per_day
        self.max_wait = max_wait
        self._clock = clock
        self._next_slot = 0.0
        self._day = date.today()
        self._used_today = 0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            if date.today() != self._day:
                self._day, self._used_today = date.today(), 0
            if self.per_day is not None and self._used_today >= self.per_day:
                raise IntelUnavailable("daily quota used up")
            now = self._clock()
            wait = self._next_slot - now
            if wait > self.max_wait:
                raise IntelUnavailable(f"rate limited for another {wait:.0f}s")
            if wait > 0:
                await asyncio.sleep(wait)
            self._next_slot = max(now, self._next_slot) + self.interval
            self._used_today += 1

    def penalize(self, seconds: float = 60.0) -> None:
        """The service said 429: back off before trying again."""
        self._next_slot = max(self._next_slot, self._clock() + seconds)


class IntelCache(Protocol):
    def get(self, key: str) -> Any | None: ...

    def set(self, key: str, value: Any, ttl_seconds: float) -> None: ...


class MemoryCache:
    def __init__(self, clock: Callable[[], float] = time.time):
        self._items: dict[str, tuple[float, Any]] = {}
        self._clock = clock

    def get(self, key: str) -> Any | None:
        item = self._items.get(key)
        if item is None or item[0] < self._clock():
            self._items.pop(key, None)
            return None
        return item[1]

    def set(self, key: str, value: Any, ttl_seconds: float) -> None:
        self._items[key] = (self._clock() + ttl_seconds, value)


class IntelClient:
    """Base class: one per service, sharing a single httpx client."""

    service: str

    def __init__(
        self,
        http: httpx.AsyncClient,
        cache: IntelCache,
        limiter: RateLimiter | None = None,
        cache_seconds: float = 12 * 3600,
    ):
        self.http = http
        self.cache = cache
        self.limiter = limiter or RateLimiter()
        self.cache_seconds = cache_seconds

    async def cached(self, kind: str, key: str, fetch: Callable[[], Awaitable[Any]]) -> Any:
        """Cache successful lookups, including "not found". Errors are never cached."""
        cache_key = f"{self.service}:{kind}:{key}"
        hit = self.cache.get(cache_key)
        if hit is not None:
            return hit["v"]  # wrapped so a cached None ("not found") is distinguishable
        value = await fetch()
        self.cache.set(cache_key, {"v": value}, self.cache_seconds)
        return value

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        await self.limiter.acquire()
        try:
            response = await self.http.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise IntelUnavailable(f"{self.service}: {type(exc).__name__}: {exc}") from exc
        if response.status_code == 429:
            self.limiter.penalize()
            raise IntelUnavailable(f"{self.service}: rate limited by the service")
        if response.status_code in (401, 403):
            raise IntelUnavailable(f"{self.service}: API key rejected ({response.status_code})")
        if response.status_code >= 500:
            raise IntelUnavailable(f"{self.service}: server error {response.status_code}")
        return response

    def json(self, response: httpx.Response) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise IntelUnavailable(f"{self.service}: invalid JSON response") from exc
