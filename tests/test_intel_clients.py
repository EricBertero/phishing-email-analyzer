import asyncio

import httpx
import pytest
import respx

from phishanalyzer.intel.abuseipdb import API as ABUSEIPDB_API
from phishanalyzer.intel.abuseipdb import AbuseIpdbClient
from phishanalyzer.intel.base import IntelUnavailable, MemoryCache, RateLimiter
from phishanalyzer.intel.rspamd import RspamdClient
from phishanalyzer.intel.spamhaus import SpamhausClient
from phishanalyzer.intel.urlhaus import API as URLHAUS_API
from phishanalyzer.intel.urlhaus import UrlhausClient
from phishanalyzer.intel.virustotal import API as VT_API
from phishanalyzer.intel.virustotal import VirusTotalClient, url_id


def run(coro):
    return asyncio.run(coro)


def make(cls, **kwargs):
    return cls(httpx.AsyncClient(), MemoryCache(), **kwargs)


# --- rate limiter / cache / error mapping ------------------------------------------------


def test_rate_limiter_daily_quota():
    limiter = RateLimiter(per_day=2)

    async def go():
        await limiter.acquire()
        await limiter.acquire()
        with pytest.raises(IntelUnavailable, match="daily quota"):
            await limiter.acquire()

    run(go())


def test_rate_limiter_refuses_long_waits_instead_of_stalling():
    now = [100.0]
    limiter = RateLimiter(per_minute=1, max_wait=5, clock=lambda: now[0])

    async def go():
        await limiter.acquire()  # next slot at 160
        with pytest.raises(IntelUnavailable, match="rate limited"):
            await limiter.acquire()
        now[0] = 160.0
        await limiter.acquire()  # slot available again

    run(go())


def test_rate_limiter_penalize():
    now = [0.0]
    limiter = RateLimiter(max_wait=5, clock=lambda: now[0])
    limiter.penalize(60)

    async def go():
        with pytest.raises(IntelUnavailable):
            await limiter.acquire()

    run(go())


def test_memory_cache_expiry():
    now = [0.0]
    cache = MemoryCache(clock=lambda: now[0])
    cache.set("k", {"v": 1}, ttl_seconds=10)
    assert cache.get("k") == {"v": 1}
    now[0] = 11
    assert cache.get("k") is None


@respx.mock
def test_not_found_is_cached_but_errors_are_not():
    client = make(VirusTotalClient, api_key="k")
    route = respx.get(f"{VT_API}/files/abc").mock(return_value=httpx.Response(404))
    assert run(client.file("abc")) is None
    assert run(client.file("abc")) is None
    assert route.call_count == 1  # second answer came from the cache

    err = respx.get(f"{VT_API}/files/def").mock(return_value=httpx.Response(503))
    for _ in range(2):
        with pytest.raises(IntelUnavailable, match="server error"):
            run(client.file("def"))
    assert err.call_count == 2


@respx.mock
@pytest.mark.parametrize(
    ("status", "match"), [(429, "rate limited"), (401, "key rejected"), (403, "key rejected")]
)
def test_http_error_mapping(status, match):
    client = make(AbuseIpdbClient, api_key="k")
    respx.get(ABUSEIPDB_API).mock(return_value=httpx.Response(status))
    with pytest.raises(IntelUnavailable, match=match):
        run(client.check("1.2.3.4"))


@respx.mock
def test_network_error_is_unavailable():
    client = make(AbuseIpdbClient, api_key="k")
    respx.get(ABUSEIPDB_API).mock(side_effect=httpx.ConnectTimeout("boom"))
    with pytest.raises(IntelUnavailable, match="ConnectTimeout"):
        run(client.check("1.2.3.4"))


# --- URLhaus ------------------------------------------------------------------------------


@respx.mock
def test_urlhaus_url_and_host():
    client = make(UrlhausClient, auth_key="secret")
    url_route = respx.post(f"{URLHAUS_API}/url/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["exe"],
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
            },
        )
    )
    result = run(client.url("http://bad.example/x.exe"))
    assert result["status"] == "online" and result["threat"] == "malware_download"
    request = url_route.calls.last.request
    assert request.headers["Auth-Key"] == "secret"
    assert b"url=http%3A%2F%2Fbad.example%2Fx.exe" in request.content

    respx.post(f"{URLHAUS_API}/host/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "url_count": "3",
                "urls": [{"url_status": "online"}, {"url_status": "offline"}],
            },
        )
    )
    host = run(client.host("bad.example"))
    assert host["url_count"] == 3 and host["online"] == 1


@respx.mock
def test_urlhaus_no_results_and_bad_status():
    client = make(UrlhausClient, auth_key="k")
    respx.post(f"{URLHAUS_API}/url/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_results"})
    )
    assert run(client.url("http://fine.example/")) is None
    respx.post(f"{URLHAUS_API}/host/").mock(
        return_value=httpx.Response(200, json={"query_status": "unknown_auth_key"})
    )
    with pytest.raises(IntelUnavailable, match="unknown_auth_key"):
        run(client.host("x.example"))


# --- AbuseIPDB / VirusTotal / rspamd ------------------------------------------------------


@respx.mock
def test_abuseipdb_check():
    client = make(AbuseIpdbClient, api_key="k")
    route = respx.get(ABUSEIPDB_API).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 87,
                    "totalReports": 12,
                    "isWhitelisted": False,
                    "countryCode": "NL",
                }
            },
        )
    )
    result = run(client.check("185.1.2.3"))
    assert result == {
        "confidence": 87,
        "reports": 12,
        "whitelisted": False,
        "usage": None,
        "country": "NL",
    }
    assert route.calls.last.request.url.params["ipAddress"] == "185.1.2.3"
    assert route.calls.last.request.headers["Key"] == "k"


def test_vt_url_id():
    assert url_id("http://example.com/") == "aHR0cDovL2V4YW1wbGUuY29tLw"


@respx.mock
def test_virustotal_file_and_url():
    client = make(VirusTotalClient, api_key="vt")
    respx.get(f"{VT_API}/files/aa").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 55, "suspicious": 1},
                        "popular_threat_classification": {
                            "suggested_threat_label": "trojan.emotet"
                        },
                        "meaningful_name": "invoice.exe",
                    }
                }
            },
        )
    )
    result = run(client.file("aa"))
    assert result["malicious"] == 55 and result["label"] == "trojan.emotet"

    route = respx.get(f"{VT_API}/urls/{url_id('http://x.example/')}").mock(
        return_value=httpx.Response(404)
    )
    assert run(client.url("http://x.example/")) is None
    assert route.calls.last.request.headers["x-apikey"] == "vt"


@respx.mock
def test_rspamd_check():
    client = make(RspamdClient, base_url="http://localhost:11333/")
    route = respx.post("http://localhost:11333/checkv2").mock(
        return_value=httpx.Response(
            200,
            json={
                "score": 16.5,
                "required_score": 15,
                "action": "reject",
                "symbols": {
                    "BAYES_SPAM": {"score": 5.1},
                    "R_SPF_ALLOW": {"score": -0.2},
                    "PHISHING": {"score": 7.0},
                },
            },
        )
    )
    result = run(client.check(b"raw message", ip="1.2.3.4", sender="a@b.example"))
    assert result["action"] == "reject" and result["score"] == 16.5
    assert result["top_symbols"] == ["PHISHING", "BAYES_SPAM"]
    assert route.calls.last.request.headers["IP"] == "1.2.3.4"
    assert route.calls.last.request.content == b"raw message"


# --- Spamhaus (DNS) -------------------------------------------------------------------------


def fake_resolver(answers: dict[str, list[str]]):
    queried: list[str] = []

    async def resolve(qname: str) -> list[str]:
        queried.append(qname)
        return answers.get(qname, [])

    return resolve, queried


def test_spamhaus_ip_query_format_and_codes():
    resolve, queried = fake_resolver(
        {"4.3.2.1.KEY.zen.dq.spamhaus.net": ["127.0.0.2", "127.0.0.10"]}
    )
    client = SpamhausClient(MemoryCache(), "KEY", resolve)
    result = run(client.ip("1.2.3.4"))
    assert queried == ["4.3.2.1.KEY.zen.dq.spamhaus.net"]
    assert result["codes"] == ["127.0.0.2", "127.0.0.10"]
    assert not result["policy_only"]
    assert "SBL (spam source)" in result["reasons"]

    run(client.ip("1.2.3.4"))
    assert len(queried) == 1  # cached


def test_spamhaus_policy_only_and_ipv6():
    resolve, queried = fake_resolver({"9.9.9.9.K.zen.dq.spamhaus.net": ["127.0.0.11"]})
    client = SpamhausClient(MemoryCache(), "K", resolve)
    assert run(client.ip("9.9.9.9"))["policy_only"]
    assert run(client.ip("2001:db8::1"))["codes"] == []
    assert len(queried) == 1


def test_spamhaus_domain_categories():
    resolve, _ = fake_resolver(
        {
            "phish.example.K.dbl.dq.spamhaus.net": ["127.0.1.4"],
            "abused.example.K.dbl.dq.spamhaus.net": ["127.0.1.104"],
        }
    )
    client = SpamhausClient(MemoryCache(), "K", resolve)
    phish = run(client.domain("Phish.Example"))
    assert phish["dangerous"] and not phish["abused_legit"]
    abused = run(client.domain("abused.example"))
    assert abused["abused_legit"] and not abused["dangerous"]
    assert run(client.domain("clean.example"))["codes"] == []


def test_spamhaus_error_codes_are_not_listings():
    resolve, _ = fake_resolver({"x.example.K.dbl.dq.spamhaus.net": ["127.255.255.254"]})
    client = SpamhausClient(MemoryCache(), "K", resolve)
    with pytest.raises(IntelUnavailable, match="refused"):
        run(client.domain("x.example"))
