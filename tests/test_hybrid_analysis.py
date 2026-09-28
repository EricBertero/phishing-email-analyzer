import asyncio

import httpx
import pytest
import respx

from phishanalyzer.intel.base import IntelClient, IntelUnavailable, MemoryCache
from phishanalyzer.intel.hybrid_analysis import API, HybridAnalysisClient


def run(coro):
    return asyncio.run(coro)


def make() -> HybridAnalysisClient:
    return HybridAnalysisClient(httpx.AsyncClient(), MemoryCache(), api_key="ha-key")


REPORT = {
    "job_id": "job1",
    "verdict": "malicious",
    "threat_score": 100,
    "av_detect": 85,
    "vx_family": "Emotet",
    "tags": ["trojan", "macro"],
}


@respx.mock
def test_overview_known_hash_and_headers():
    route = respx.get(f"{API}/overview/abc").mock(return_value=httpx.Response(200, json=REPORT))
    result = run(make().overview("abc"))
    assert result == {
        "verdict": "malicious",
        "threat_score": 100,
        "av_detect": 85,
        "family": "Emotet",
        "tags": ["trojan", "macro"],
        "job_id": "job1",
    }
    sent = route.calls.last.request.headers
    assert sent["api-key"] == "ha-key"
    assert sent["user-agent"] == "Falcon Sandbox"


@respx.mock
def test_overview_unknown_or_verdictless_hash_is_none():
    respx.get(f"{API}/overview/new").mock(return_value=httpx.Response(404))
    respx.get(f"{API}/overview/static").mock(
        return_value=httpx.Response(200, json={"sha256": "static", "verdict": None})
    )
    client = make()
    assert run(client.overview("new")) is None
    assert run(client.overview("static")) is None


@respx.mock
def test_overview_errors_are_unavailable():
    respx.get(f"{API}/overview/x").mock(return_value=httpx.Response(429))
    with pytest.raises(IntelUnavailable, match="rate limited"):
        run(make().overview("x"))


@respx.mock
def test_submit_file_sends_multipart_and_privacy_flags():
    route = respx.post(f"{API}/submit/file").mock(
        return_value=httpx.Response(201, json={"job_id": "j42", "sha256": "abc"})
    )
    result = run(make().submit_file("invoice.pdf", b"%PDF-1.7 body", 120))
    assert result == {"job_id": "j42", "sha256": "abc"}
    request = route.calls.last.request
    assert request.headers["content-type"].startswith("multipart/form-data")
    body = request.content
    assert b'filename="invoice.pdf"' in body and b"%PDF-1.7 body" in body
    assert b'name="environment_id"' in body and b"120" in body
    # Not shared with third parties or the community unless the user opted in.
    assert b'name="no_share_third_party"\r\n\r\ntrue' in body
    assert b'name="allow_community_access"\r\n\r\nfalse' in body


@respx.mock
def test_submit_file_opt_in_sharing():
    route = respx.post(f"{API}/submit/file").mock(
        return_value=httpx.Response(201, json={"job_id": "j"})
    )
    run(make().submit_file("a.bin", b"x", 300, share_third_party=True))
    assert b'name="no_share_third_party"\r\n\r\nfalse' in route.calls.last.request.content


@respx.mock
@pytest.mark.parametrize(
    "response", [httpx.Response(400, json={}), httpx.Response(201, json={"no": "job"})]
)
def test_submit_file_failures(response):
    respx.post(f"{API}/submit/file").mock(return_value=response)
    with pytest.raises(IntelUnavailable):
        run(make().submit_file("a.bin", b"x", 120))


@respx.mock
def test_submissions_are_never_cached():
    route = respx.post(f"{API}/submit/file").mock(
        return_value=httpx.Response(201, json={"job_id": "j"})
    )
    client = make()
    run(client.submit_file("a.bin", b"x", 120))
    run(client.submit_file("a.bin", b"x", 120))
    assert route.call_count == 2


@respx.mock
def test_state_and_summary():
    respx.get(f"{API}/report/j1/state").mock(
        return_value=httpx.Response(200, json={"state": "in_progress"})
    )
    respx.get(f"{API}/report/j1/summary").mock(return_value=httpx.Response(200, json=REPORT))
    client = make()
    assert run(client.state("j1")) == "IN_PROGRESS"
    assert run(client.summary("j1"))["verdict"] == "malicious"
    respx.get(f"{API}/report/gone/state").mock(return_value=httpx.Response(404))
    with pytest.raises(IntelUnavailable, match="not found"):
        run(client.state("gone"))


def test_concurrent_identical_lookups_share_one_request():
    """VirusTotal and sandbox analyzers ask about the same hash at once: one API call."""
    calls = 0

    class Client(IntelClient):
        service = "demo"

    async def scenario():
        nonlocal calls
        client = Client(httpx.AsyncClient(), MemoryCache())

        async def fetch():
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.05)
            return {"malicious": 1}

        results = await asyncio.gather(*(client.cached("file", "abc", fetch) for _ in range(5)))
        assert results == [{"malicious": 1}] * 5
        await client.cached("file", "abc", fetch)  # now from the cache

    asyncio.run(scenario())
    assert calls == 1


def test_concurrent_lookups_share_failures_and_recover():
    calls = 0

    class Client(IntelClient):
        service = "demo"

    async def scenario():
        nonlocal calls
        client = Client(httpx.AsyncClient(), MemoryCache())

        async def flaky():
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.02)
            if calls == 1:
                raise IntelUnavailable("down")
            return "ok"

        first = await asyncio.gather(
            *(client.cached("k", "x", flaky) for _ in range(3)), return_exceptions=True
        )
        assert all(isinstance(r, IntelUnavailable) for r in first)
        assert await client.cached("k", "x", flaky) == "ok"  # errors are not cached

    asyncio.run(scenario())
    assert calls == 2
