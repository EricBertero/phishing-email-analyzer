"""rspamd: a full spam filter (Bayes, fuzzy hashes, RBLs, heuristics) running locally."""

from __future__ import annotations

from typing import Any

from phishanalyzer.intel.base import IntelClient, IntelUnavailable


class RspamdClient(IntelClient):
    service = "rspamd"

    def __init__(self, *args: Any, base_url: str, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.base_url = base_url.rstrip("/")

    async def check(
        self, raw: bytes, ip: str | None = None, sender: str | None = None
    ) -> dict[str, Any]:
        headers = {}
        if ip:
            headers["IP"] = ip  # lets rspamd apply its IP rules to the real origin
        if sender:
            headers["From"] = sender
        response = await self.request(
            "POST", f"{self.base_url}/checkv2", content=raw, headers=headers
        )
        if response.status_code != 200:
            raise IntelUnavailable(f"rspamd: HTTP {response.status_code}")
        body = self.json(response)
        symbols = body.get("symbols") or {}
        top = sorted(
            ((name, float(sym.get("score") or 0)) for name, sym in symbols.items()),
            key=lambda item: item[1],
            reverse=True,
        )
        return {
            "score": float(body.get("score") or 0),
            "required": float(body.get("required_score") or 15),
            "action": body.get("action") or "no action",
            "top_symbols": [name for name, score in top[:8] if score > 0],
        }
