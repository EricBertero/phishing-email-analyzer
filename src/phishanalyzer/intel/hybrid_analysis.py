"""Hybrid Analysis (CrowdStrike Falcon Sandbox) API v2.

Two very different operations live here:

* `overview(sha256)`: look up an existing report for a hash. Private and free of side
  effects, so it is always allowed.
* `submit_file(...)`: upload a file for detonation. The file leaves the machine, so the
  caller (the sandbox worker) only does this when `sandbox_upload` permits it.

NOTE: request shapes follow the public API v2 documentation as remembered when this was
written; run `phish doctor` with a real key to confirm them.
"""

from __future__ import annotations

from typing import Any

from phishanalyzer.intel.base import IntelClient, IntelUnavailable

API = "https://www.hybrid-analysis.com/api/v2"

# The API rejects requests without this user agent.
USER_AGENT = "Falcon Sandbox"

# Job states reported by GET /report/{id}/state.
UPLOAD_TIMEOUT_SECONDS = 180  # large files over a slow uplink

STATE_DONE = "SUCCESS"
STATE_ERROR = "ERROR"
STATES_RUNNING = {"IN_QUEUE", "IN_PROGRESS"}


def _summarise(data: dict[str, Any]) -> dict[str, Any]:
    """The few fields we score on, from a report summary or overview."""
    threat_score = data.get("threat_score")
    av_detect = data.get("av_detect")
    return {
        "verdict": (data.get("verdict") or "no verdict").lower(),
        "threat_score": int(threat_score) if threat_score is not None else None,
        "av_detect": int(av_detect) if av_detect is not None else None,
        "family": data.get("vx_family") or None,
        "tags": (data.get("tags") or [])[:10],
        "job_id": data.get("job_id"),
    }


class HybridAnalysisClient(IntelClient):
    service = "hybrid_analysis"

    def __init__(self, *args: Any, api_key: str, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._headers = {"api-key": api_key, "user-agent": USER_AGENT, "accept": "application/json"}

    async def overview(self, sha256: str) -> dict[str, Any] | None:
        """Existing verdict for a file hash, or None if Hybrid Analysis has never seen it."""

        async def fetch() -> dict[str, Any] | None:
            response = await self.request("GET", f"{API}/overview/{sha256}", headers=self._headers)
            if response.status_code == 404:
                return None
            if response.status_code != 200:
                raise IntelUnavailable(f"hybrid_analysis: HTTP {response.status_code}")
            data = self.json(response)
            # Hashes that were only ever statically scanned come back without a verdict.
            if not isinstance(data, dict) or not data.get("verdict"):
                return None
            return _summarise(data)

        return await self.cached("overview", sha256, fetch)

    async def submit_file(
        self,
        filename: str,
        data: bytes,
        environment_id: int,
        share_third_party: bool = False,
    ) -> dict[str, Any]:
        """Upload a file for analysis. Never cached: every call is a real submission."""
        response = await self.request(
            "POST",
            f"{API}/submit/file",
            headers=self._headers,
            timeout=UPLOAD_TIMEOUT_SECONDS,
            files={"file": (filename, data)},
            data={
                "environment_id": str(environment_id),
                "no_share_third_party": str(not share_third_party).lower(),
                "allow_community_access": "false",
            },
        )
        if response.status_code not in (200, 201):
            raise IntelUnavailable(f"hybrid_analysis: submit failed, HTTP {response.status_code}")
        body = self.json(response)
        job_id = body.get("job_id")
        if not job_id:
            raise IntelUnavailable("hybrid_analysis: submit response had no job_id")
        return {"job_id": job_id, "sha256": body.get("sha256")}

    async def state(self, job_id: str) -> str:
        """SUCCESS, ERROR, IN_QUEUE or IN_PROGRESS. Not cached: it changes."""
        response = await self.request("GET", f"{API}/report/{job_id}/state", headers=self._headers)
        if response.status_code == 404:
            raise IntelUnavailable(f"hybrid_analysis: job {job_id} not found")
        if response.status_code != 200:
            raise IntelUnavailable(f"hybrid_analysis: HTTP {response.status_code}")
        return str(self.json(response).get("state") or "").upper()

    async def summary(self, job_id: str) -> dict[str, Any]:
        response = await self.request(
            "GET", f"{API}/report/{job_id}/summary", headers=self._headers
        )
        if response.status_code != 200:
            raise IntelUnavailable(f"hybrid_analysis: HTTP {response.status_code}")
        return _summarise(self.json(response))
