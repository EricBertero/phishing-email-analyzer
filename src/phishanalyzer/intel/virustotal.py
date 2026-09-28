"""VirusTotal v3: file-hash and URL verdicts from ~70 antivirus engines.

Only lookups of things VirusTotal already knows are made here. Uploading files is a
sandbox decision (Phase 5), because uploads become visible to other VirusTotal users.
"""

from __future__ import annotations

import base64
from typing import Any

from phishanalyzer.intel.base import IntelClient, IntelUnavailable

API = "https://www.virustotal.com/api/v3"


def url_id(url: str) -> str:
    """VirusTotal's identifier for a URL: unpadded URL-safe base64 of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotalClient(IntelClient):
    service = "virustotal"

    def __init__(self, *args: Any, api_key: str, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._headers = {"x-apikey": api_key}

    async def _get(self, path: str) -> dict[str, Any] | None:
        response = await self.request("GET", f"{API}/{path}", headers=self._headers)
        if response.status_code == 404:
            return None  # never seen by VirusTotal
        if response.status_code != 200:
            raise IntelUnavailable(f"virustotal: HTTP {response.status_code}")
        attributes = (self.json(response).get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        classification = attributes.get("popular_threat_classification") or {}
        return {
            "malicious": int(stats.get("malicious") or 0),
            "suspicious": int(stats.get("suspicious") or 0),
            "harmless": int(stats.get("harmless") or 0),
            "undetected": int(stats.get("undetected") or 0),
            "label": classification.get("suggested_threat_label"),
            "name": attributes.get("meaningful_name"),
        }

    async def file(self, sha256: str) -> dict[str, Any] | None:
        return await self.cached("file", sha256, lambda: self._get(f"files/{sha256}"))

    async def url(self, url: str) -> dict[str, Any] | None:
        return await self.cached("url", url, lambda: self._get(f"urls/{url_id(url)}"))
