"""SPF / DKIM / DMARC results, as recorded by the recipient's mail server."""

from __future__ import annotations

import re

from phishanalyzer.domains import domain_of_address, same_org
from phishanalyzer.models import Email, Finding, Severity

_RESULT = re.compile(
    r"\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)(.*?)(?=;|\b(?:spf|dkim|dmarc|arc)=|$)", re.I
)
_DKIM_DOMAIN = re.compile(r"header\.(?:d|i)=@?([^\s;]+)", re.I)

# SPF result -> (points, severity). `pass` is reported as info with 0 points.
_SPF = {
    "fail": (15, Severity.MEDIUM),
    "softfail": (8, Severity.LOW),
    "neutral": (5, Severity.LOW),
    "none": (5, Severity.LOW),
    "temperror": (3, Severity.LOW),
    "permerror": (5, Severity.LOW),
}


def parse_auth_results(value: str) -> dict[str, list[tuple[str, str]]]:
    """`Authentication-Results` -> {"dkim": [("pass", "header.i=@x.com ...")], ...}."""
    results: dict[str, list[tuple[str, str]]] = {}
    for method, result, props in _RESULT.findall(value):
        results.setdefault(method.lower(), []).append((result.lower(), props))
    return results


class AuthAnalyzer:
    name = "auth"

    async def analyze(self, email: Email) -> list[Finding]:
        # Only the topmost header was written by the recipient's server; lower ones could
        # have been injected by the sender.
        header = email.header("Authentication-Results")
        if header is None:
            spf_header = email.header("Received-SPF")
            if spf_header is None:
                return [
                    Finding(
                        signal="auth.no_results",
                        points=0,
                        severity=Severity.INFO,
                        message="No authentication results recorded (forwarded, exported or "
                        "internal message); SPF/DKIM/DMARC could not be evaluated.",
                    )
                ]
            header = "spf=" + spf_header.split()[0] if spf_header.split() else ""

        results = parse_auth_results(header)
        from_domain = domain_of_address(email.from_addr)
        return [
            *self._spf(results.get("spf", [])),
            *self._dkim(results.get("dkim", []), from_domain),
            *self._dmarc(results.get("dmarc", [])),
        ]

    def _spf(self, results: list[tuple[str, str]]) -> list[Finding]:
        result = results[0][0] if results else "none"
        if result == "pass":
            return [
                Finding(
                    signal="auth.spf_pass", points=0, severity=Severity.INFO, message="SPF passed."
                )
            ]
        points, severity = _SPF.get(result, (5, Severity.LOW))
        return [
            Finding(
                signal=f"auth.spf_{result}",
                points=points,
                severity=severity,
                message=f"SPF result is '{result}': the sending server is not authorised "
                "by the envelope sender's domain.",
                evidence={"spf": result},
            )
        ]

    def _dkim(self, results: list[tuple[str, str]], from_domain: str | None) -> list[Finding]:
        passing = [props for result, props in results if result == "pass"]
        if not passing:
            failed = any(result == "fail" for result, _ in results)
            return [
                Finding(
                    signal="auth.dkim_fail" if failed else "auth.dkim_none",
                    points=15 if failed else 5,
                    severity=Severity.MEDIUM if failed else Severity.LOW,
                    message="DKIM signature failed verification: the message may have been "
                    "altered or forged."
                    if failed
                    else "Message is not DKIM-signed.",
                )
            ]
        signers = [m.group(1).lower() for p in passing if (m := _DKIM_DOMAIN.search(p))]
        if from_domain and signers and not any(same_org(s, from_domain) for s in signers):
            return [
                Finding(
                    signal="auth.dkim_unaligned",
                    points=5,
                    severity=Severity.LOW,
                    message="DKIM passed, but only for a domain unrelated to the From address.",
                    evidence={"signers": signers, "from_domain": from_domain},
                )
            ]
        return [
            Finding(
                signal="auth.dkim_pass",
                points=0,
                severity=Severity.INFO,
                message="DKIM passed.",
                evidence={"signers": signers},
            )
        ]

    def _dmarc(self, results: list[tuple[str, str]]) -> list[Finding]:
        result = results[0][0] if results else "none"
        if result == "pass":
            return [
                Finding(
                    signal="auth.dmarc_pass",
                    points=0,
                    severity=Severity.INFO,
                    message="DMARC passed: the From domain is authenticated.",
                )
            ]
        if result == "fail":
            return [
                Finding(
                    signal="auth.dmarc_fail",
                    points=30,
                    severity=Severity.HIGH,
                    message="DMARC failed: the From domain did not authenticate this "
                    "message. A strong sign of spoofing.",
                )
            ]
        return [
            Finding(
                signal="auth.dmarc_none",
                points=10,
                severity=Severity.LOW,
                message="No DMARC result: nothing ties the visible From domain to the "
                "authenticated sender.",
                evidence={"dmarc": result},
            )
        ]
