"""URLhaus (abuse.ch): known malware-distribution URLs and hosts."""

from __future__ import annotations

from typing import Any

from phishanalyzer.intel.base import IntelClient, IntelUnavailable

API = "https://urlhaus-api.abuse.ch/v1"


class UrlhausClient(IntelClient):
    service = "urlhaus"

    def __init__(self, *args: Any, auth_key: str, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._headers = {"Auth-Key": auth_key}

    async def _post(self, endpoint: str, data: dict[str, str]) -> dict[str, Any]:
        response = await self.request(
            "POST", f"{API}/{endpoint}/", data=data, headers=self._headers
        )
        if response.status_code != 200:
            raise IntelUnavailable(f"urlhaus: HTTP {response.status_code}")
        body = self.json(response)
        status = body.get("query_status")
        if status not in ("ok", "no_results", "invalid_url", "invalid_host"):
            raise IntelUnavailable(f"urlhaus: query_status={status}")
        return body

    async def url(self, url: str) -> dict[str, Any] | None:
        """{status: online|offline|unknown, threat, tags, reference}, or None if unknown."""

        async def fetch() -> dict[str, Any] | None:
            body = await self._post("url", {"url": url})
            if body["query_status"] != "ok":
                return None
            return {
                "status": body.get("url_status"),
                "threat": body.get("threat"),
                "tags": body.get("tags") or [],
                "reference": body.get("urlhaus_reference"),
            }

        return await self.cached("url", url, fetch)

    async def host(self, host: str) -> dict[str, Any] | None:
        """{url_count, online, reference}, or None if the host was never reported."""

        async def fetch() -> dict[str, Any] | None:
            body = await self._post("host", {"host": host})
            if body["query_status"] != "ok":
                return None
            urls = body.get("urls") or []
            return {
                "url_count": int(body.get("url_count") or len(urls)),
                "online": sum(1 for u in urls if u.get("url_status") == "online"),
                "reference": body.get("urlhaus_reference"),
            }

        return await self.cached("host", host, fetch)
