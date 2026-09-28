import asyncio
import hashlib

import pytest
from conftest import make_email, run, signals

from phishanalyzer.analyzers import build_analyzers
from phishanalyzer.analyzers.intel import (
    AbuseIpdbAnalyzer,
    SpamhausAnalyzer,
    UrlhausAnalyzer,
    VirusTotalAnalyzer,
)
from phishanalyzer.analyzers.spam import RspamdAnalyzer
from phishanalyzer.config import Secrets, Settings
from phishanalyzer.intel import Intel
from phishanalyzer.intel.base import IntelUnavailable
from phishanalyzer.models import Finding, Level, Severity
from phishanalyzer.scoring import score_findings


class Fake:
    """Stand-in client: method name -> {argument: result or exception}."""

    def __init__(self, **tables):
        self.tables = tables
        self.calls: list[tuple[str, str]] = []

    def __getattr__(self, method):
        table = self.tables.get(method, {})

        async def call(arg, *rest, **kwargs):
            self.calls.append((method, arg))
            result = table.get(arg, table.get("*"))
            if isinstance(result, Exception):
                raise result
            return result

        return call


def links(*urls: str) -> str:
    return "".join(f'<a href="{u}">link</a>' for u in urls)


def by_signal(findings: list[Finding]) -> dict[str, Finding]:
    return {f.signal: f for f in findings}


# --- URLhaus --------------------------------------------------------------------------------


def test_urlhaus_online_url_forces_critical(settings):
    client = Fake(
        url={"http://bad.example/a.exe": {"status": "online", "threat": "malware_download"}},
        host={"*": None},
    )
    email = make_email(html=links("http://bad.example/a.exe", "https://ok.example/"))
    found = by_signal(run(UrlhausAnalyzer(client, settings), email))
    assert found["urls.urlhaus_online"].force_critical


def test_urlhaus_known_offline_and_host(settings):
    client = Fake(
        url={"*": {"status": "offline", "threat": "malware_download"}},
        host={"bad.example": {"url_count": 4, "online": 0, "reference": None}},
    )
    email = make_email(html=links("http://bad.example/old"))
    assert signals(run(UrlhausAnalyzer(client, settings), email)) == {
        "urls.urlhaus_known",
        "urls.urlhaus_host_known",
    }


def test_urlhaus_errors_make_verdict_partial(settings):
    client = Fake(url={"*": IntelUnavailable("down")}, host={"*": None})
    findings = run(UrlhausAnalyzer(client, settings), make_email(html=links("http://x.example/")))
    assert [f.signal for f in findings] == ["urlhaus.unavailable"]
    assert score_findings(findings, settings).partial


def test_urlhaus_host_limit(settings):
    settings.intel.max_hosts_per_email = 2
    client = Fake(url={"*": None}, host={"*": None})
    email = make_email(html=links(*(f"http://h{i}.example/" for i in range(5))))
    run(UrlhausAnalyzer(client, settings), email)
    assert len([c for c in client.calls if c[0] == "host"]) == 2


# --- Spamhaus --------------------------------------------------------------------------------


def dbl(*codes, dangerous=False, abused=False):
    return {"codes": list(codes), "reasons": ["x"], "dangerous": dangerous, "abused_legit": abused}


CLEAN_DBL = dbl()


def test_spamhaus_sender_ip_and_domains(settings):
    client = Fake(
        ip={"52.10.20.30": {"codes": ["127.0.0.2"], "reasons": ["SBL"], "policy_only": False}},
        domain={
            "example.com": dbl("127.0.1.2"),
            "evil-login.com": dbl("127.0.1.4", dangerous=True),
            "abused-site.net": dbl("127.0.1.104", abused=True),
            "*": CLEAN_DBL,
        },
    )
    email = make_email(
        html=links("https://evil-login.com/login", "https://abused-site.net/x", "https://fine.org/")
    )
    found = by_signal(run(SpamhausAnalyzer(client, settings), email))
    assert found["reputation.ip_blocklisted"].points == 25
    assert found["reputation.sender_domain_blocklisted"].points == 25
    assert found["reputation.link_domain_blocklisted"].force_critical
    assert not found["reputation.link_domain_abused"].force_critical


def test_spamhaus_policy_listing_is_weak(settings):
    client = Fake(
        ip={"*": {"codes": ["127.0.0.10"], "reasons": ["PBL"], "policy_only": True}},
        domain={"*": CLEAN_DBL},
    )
    found = by_signal(run(SpamhausAnalyzer(client, settings), make_email()))
    assert found["reputation.ip_policy_listed"].points == 5


def test_spamhaus_skips_private_sender_ip(settings):
    client = Fake(domain={"*": CLEAN_DBL})
    email = make_email(authenticated=False)
    assert run(SpamhausAnalyzer(client, settings), email) == []
    assert all(method == "domain" for method, _ in client.calls)


def test_dbl_listing_plus_dmarc_fail_is_critical(settings):
    client = Fake(
        ip={"*": {"codes": [], "reasons": [], "policy_only": False}},
        domain={"example.com": dbl("127.0.1.2"), "*": CLEAN_DBL},
    )
    email = make_email()
    findings = run(SpamhausAnalyzer(client, settings), email)
    findings.append(
        Finding(signal="auth.dmarc_fail", points=30, severity=Severity.HIGH, message="x")
    )
    verdict = score_findings(findings, settings)
    assert verdict.level is Level.CRITICAL
    assert "combo.blocklisted_spoof" in {f.signal for f in verdict.findings}


# --- AbuseIPDB --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("confidence", "whitelisted", "points"),
    [(90, False, 25), (40, False, 10), (10, False, None), (100, True, None)],
)
def test_abuseipdb_thresholds(confidence, whitelisted, points):
    client = Fake(
        check={
            "*": {
                "confidence": confidence,
                "reports": 3,
                "whitelisted": whitelisted,
                "usage": None,
                "country": None,
            }
        }
    )
    findings = run(AbuseIpdbAnalyzer(client), make_email())
    if points is None:
        assert findings == []
    else:
        assert findings[0].signal == "reputation.ip_abuse_reports"
        assert findings[0].points == points


def test_abuseipdb_unavailable():
    client = Fake(check={"*": IntelUnavailable("quota")})
    [finding] = run(AbuseIpdbAnalyzer(client), make_email())
    assert finding.unavailable


# --- VirusTotal --------------------------------------------------------------------------------


def vt(malicious=0, suspicious=0, label=None):
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": 0,
        "undetected": 60,
        "label": label,
        "name": None,
    }


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_vt_attachment_verdicts(settings):
    files = {
        sha(b"evil"): vt(malicious=40, label="trojan.x"),
        sha(b"meh"): vt(malicious=1),
        sha(b"new"): None,
        sha(b"fine"): vt(),
    }
    client = Fake(file=files, url={"*": None})
    email = make_email(
        attachments=[("a.exe", b"evil"), ("b.doc", b"meh"), ("c.pdf", b"new"), ("d.pdf", b"fine")]
    )
    found = by_signal(run(VirusTotalAnalyzer(client, settings), email))
    assert found["attachments.vt_malicious"].force_critical
    assert "trojan.x" in found["attachments.vt_malicious"].message
    assert found["attachments.vt_detections"].points == 25
    assert found["attachments.vt_unknown"].points == 0
    assert found["attachments.vt_clean"].points == 0


def test_vt_attachments_before_urls_and_url_cap(settings):
    settings.intel.vt_max_urls_per_email = 1
    client = Fake(file={"*": vt()}, url={"*": vt(malicious=10)})
    email = make_email(
        html=links("https://a.example/", "https://b.example/", "https://example.com/own"),
        attachments=[("x.pdf", b"%PDF")],
    )
    found = by_signal(run(VirusTotalAnalyzer(client, settings), email))
    assert found["urls.vt_malicious"].force_critical
    assert [m for m, _ in client.calls] == ["file", "url"]
    # The sender's own domain (example.com) is never spent quota on.
    assert ("url", "https://example.com/own") not in client.calls


def test_vt_quota_exhausted_is_partial(settings):
    client = Fake(file={"*": IntelUnavailable("daily quota used up")}, url={"*": None})
    findings = run(VirusTotalAnalyzer(client, settings), make_email(attachments=[("a", b"x")]))
    assert score_findings(findings, settings).partial


# --- rspamd ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("action", "points"), [("reject", 25), ("add header", 15), ("greylist", 5), ("no action", 0)]
)
def test_rspamd_actions(action, points):
    client = Fake(
        check={"*": {"score": 9.0, "required": 15.0, "action": action, "top_symbols": []}}
    )
    [finding] = run(RspamdAnalyzer(client), make_email())
    assert finding.signal == "spam.rspamd" and finding.points == points
    assert client.calls[0][1].startswith(b"Received:")  # the raw message is sent


# --- wiring ------------------------------------------------------------------------------------


def test_build_analyzers_only_enables_configured_services():
    settings = Settings(secrets=Secrets(_env_file=None))
    assert {a.name for a in build_analyzers(settings, None)} == {
        "auth",
        "headers",
        "spam",
        "content",
        "urls",
        "attachments",
    }
    keyed = Settings(secrets=Secrets(_env_file=None, urlhaus_auth_key="u", virustotal_api_key="v"))

    async def names():
        intel = Intel(keyed)
        try:
            return {a.name for a in build_analyzers(keyed, intel)}, intel.enabled
        finally:
            await intel.aclose()

    analyzer_names, enabled = asyncio.run(names())
    assert {"urlhaus", "virustotal"} <= analyzer_names
    assert "spamhaus" not in analyzer_names
    assert enabled == ["urlhaus", "virustotal"]
