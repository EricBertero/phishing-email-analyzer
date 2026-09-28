"""Threat-intel clients. Only services with an API key (or URL) configured are created."""

from __future__ import annotations

import httpx

from phishanalyzer import __version__
from phishanalyzer.config import Settings
from phishanalyzer.intel.abuseipdb import AbuseIpdbClient
from phishanalyzer.intel.base import (
    IntelCache,
    IntelClient,
    IntelUnavailable,
    MemoryCache,
    RateLimiter,
)
from phishanalyzer.intel.rspamd import RspamdClient
from phishanalyzer.intel.spamhaus import Resolve, SpamhausClient, dns_resolve
from phishanalyzer.intel.urlhaus import UrlhausClient
from phishanalyzer.intel.virustotal import VirusTotalClient

__all__ = [
    "Intel",
    "IntelCache",
    "IntelClient",
    "IntelUnavailable",
    "MemoryCache",
    "RateLimiter",
]


class Intel:
    """Holds one shared HTTP client and the enabled service clients."""

    def __init__(
        self,
        settings: Settings,
        cache: IntelCache | None = None,
        http: httpx.AsyncClient | None = None,
        resolve: Resolve = dns_resolve,
    ):
        cfg = settings.intel
        self.cache = cache if cache is not None else MemoryCache()
        self.http = http or httpx.AsyncClient(
            timeout=cfg.timeout_seconds,
            headers={"User-Agent": f"phishanalyzer/{__version__}"},
            follow_redirects=False,
        )
        ttl = cfg.cache_hours * 3600
        common = {"cache_seconds": ttl}

        key = settings.secret("urlhaus_auth_key")
        self.urlhaus = (
            UrlhausClient(
                self.http, self.cache, RateLimiter(per_minute=120), auth_key=key, **common
            )
            if key
            else None
        )
        key = settings.secret("abuseipdb_api_key")
        self.abuseipdb = (
            AbuseIpdbClient(self.http, self.cache, RateLimiter(per_day=1000), api_key=key, **common)
            if key
            else None
        )
        key = settings.secret("virustotal_api_key")
        self.virustotal = (
            VirusTotalClient(
                self.http,
                self.cache,
                # Free tier: 4/min, 500/day. Wait up to a minute for a slot, then
                # report the lookup unavailable (re-checked later).
                RateLimiter(per_minute=4, per_day=500, max_wait=65),
                api_key=key,
                **common,
            )
            if key
            else None
        )
        key = settings.secret("spamhaus_dqs_key")
        self.spamhaus = SpamhausClient(self.cache, key, resolve, ttl) if key else None
        # rspamd scans the full message, so its results are never cached.
        self.rspamd = (
            RspamdClient(self.http, MemoryCache(), base_url=cfg.rspamd_url, cache_seconds=0)
            if cfg.rspamd_url
            else None
        )

    @property
    def enabled(self) -> list[str]:
        clients = [self.urlhaus, self.abuseipdb, self.virustotal, self.spamhaus, self.rspamd]
        return [c.service for c in clients if c is not None]

    async def aclose(self) -> None:
        await self.http.aclose()
