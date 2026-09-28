"""AbuseIPDB: crowd-sourced reports of abusive IP addresses."""

from __future__ import annotations

from typing import Any

from phishanalyzer.intel.base import IntelClient, IntelUnavailable

API = "https://api.abuseipdb.com/api/v2/check"


class AbuseIpdbClient(IntelClient):
    service = "abuseipdb"

    def __init__(self, *args: Any, api_key: str, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._headers = {"Key": api_key, "Accept": "application/json"}

    async def check(self, ip: str) -> dict[str, Any]:
        async def fetch() -> dict[str, Any]:
            response = await self.request(
                "GET", API, params={"ipAddress": ip, "maxAgeInDays": 90}, headers=self._headers
            )
            if response.status_code != 200:
                raise IntelUnavailable(f"abuseipdb: HTTP {response.status_code}")
            data = self.json(response).get("data") or {}
            return {
                "confidence": int(data.get("abuseConfidenceScore") or 0),
                "reports": int(data.get("totalReports") or 0),
                "whitelisted": bool(data.get("isWhitelisted")),
                "usage": data.get("usageType"),
                "country": data.get("countryCode"),
            }

        return await self.cached("ip", ip, fetch)
