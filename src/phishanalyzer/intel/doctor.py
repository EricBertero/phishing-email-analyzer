"""`phish doctor`: verify each configured integration with a known test indicator."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from phishanalyzer.intel import Intel
from phishanalyzer.intel.base import IntelUnavailable

# sha256 of the EICAR antivirus test file: harmless, but every engine flags it.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

TEST_MESSAGE = (
    b"From: doctor@example.com\r\nTo: you@example.com\r\nSubject: phish doctor\r\n"
    b"Message-ID: <doctor@example.com>\r\n\r\nConnectivity test.\r\n"
)


@dataclass
class CheckResult:
    service: str
    ok: bool
    detail: str


async def _check(service: str, probe: Callable[[], Awaitable[str]]) -> CheckResult:
    try:
        return CheckResult(service, True, await probe())
    except IntelUnavailable as exc:
        return CheckResult(service, False, str(exc))


async def run_checks(intel: Intel) -> list[CheckResult]:
    results = []
    if urlhaus := intel.urlhaus:

        async def probe_urlhaus() -> str:
            await urlhaus.host("example.com")
            return "API key accepted"

        results.append(await _check("urlhaus", probe_urlhaus))

    if abuseipdb := intel.abuseipdb:

        async def probe_abuseipdb() -> str:
            result = await abuseipdb.check("8.8.8.8")
            return f"8.8.8.8 -> confidence {result['confidence']}%"

        results.append(await _check("abuseipdb", probe_abuseipdb))

    if spamhaus := intel.spamhaus:

        async def probe_spamhaus() -> str:
            ip = await spamhaus.ip("127.0.0.2")  # permanent test listing
            domain = await spamhaus.domain("dbltest.com")  # permanent test listing
            if not ip["codes"] or not domain["codes"]:
                raise IntelUnavailable(
                    "test entries not listed: check the DQS key and that DNS works"
                )
            return f"ZEN test IP {ip['codes']}, DBL test domain {domain['codes']}"

        results.append(await _check("spamhaus", probe_spamhaus))

    if virustotal := intel.virustotal:

        async def probe_virustotal() -> str:
            result = await virustotal.file(EICAR_SHA256)
            if not result:
                raise IntelUnavailable("EICAR test file not found (unexpected)")
            return f"EICAR test file flagged by {result['malicious']} engines"

        results.append(await _check("virustotal", probe_virustotal))

    if rspamd := intel.rspamd:

        async def probe_rspamd() -> str:
            result = await rspamd.check(TEST_MESSAGE)
            return f"test message score {result['score']:.1f} ({result['action']})"

        results.append(await _check("rspamd", probe_rspamd))
    return results
