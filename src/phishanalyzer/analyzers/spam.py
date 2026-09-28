"""Spam verdicts left by upstream filters (SpamAssassin, rspamd, Exchange Online)."""

from __future__ import annotations

import re

from phishanalyzer.intel.base import IntelUnavailable
from phishanalyzer.intel.rspamd import RspamdClient
from phishanalyzer.models import Email, Finding, Severity

_SA_SCORE = re.compile(r"score=(-?\d+(?:\.\d+)?)", re.I)
_SA_REQUIRED = re.compile(r"required=(-?\d+(?:\.\d+)?)", re.I)
_SCL = re.compile(r"SCL:\s*(-?\d+)", re.I)


class SpamHeaderAnalyzer:
    """Reads existing spam-filter headers.

    Senders can forge these headers, but only to make a message look *cleaner*, so only
    spam-positive verdicts are scored. Negative ones are ignored rather than trusted.
    """

    name = "spam"

    async def analyze(self, email: Email) -> list[Finding]:
        findings: list[Finding] = []
        status = email.header("X-Spam-Status") or ""
        flag = (email.header("X-Spam-Flag") or "").strip().lower()
        score_text = email.header("X-Spam-Score")
        score_match = _SA_SCORE.search(status)
        score = float(score_match.group(1)) if score_match else _to_float(score_text)
        required_match = _SA_REQUIRED.search(status)
        required = float(required_match.group(1)) if required_match else 5.0

        if (
            status.lower().startswith("yes")
            or flag == "yes"
            or (score is not None and score >= required)
        ):
            findings.append(
                Finding(
                    signal="spam.filter_flagged",
                    points=20,
                    severity=Severity.MEDIUM,
                    message="An upstream spam filter flagged this message as spam"
                    + (
                        f" (score {score:g}, threshold {required:g})." if score is not None else "."
                    ),
                    evidence={"score": score, "required": required},
                )
            )

        scl_source = (
            email.header("X-MS-Exchange-Organization-SCL")
            or email.header("X-Forefront-Antispam-Report")
            or ""
        )
        scl_match = _SCL.search(scl_source) or re.fullmatch(r"\s*(-?\d+)\s*", scl_source)
        if scl_match and int(scl_match.group(1)) >= 5:
            findings.append(
                Finding(
                    signal="spam.exchange_scl",
                    points=20,
                    severity=Severity.MEDIUM,
                    message=f"Microsoft Exchange rated this message spam (SCL "
                    f"{scl_match.group(1)}).",
                    evidence={"scl": int(scl_match.group(1))},
                )
            )
        return findings


def _to_float(value: str | None) -> float | None:
    try:
        return float(value) if value else None
    except ValueError:
        return None


# rspamd action -> (points, severity). "no action" scores nothing.
_RSPAMD_ACTIONS = {
    "reject": (25, Severity.HIGH),
    "rewrite subject": (15, Severity.MEDIUM),
    "add header": (15, Severity.MEDIUM),
    "soft reject": (5, Severity.LOW),
    "greylist": (5, Severity.LOW),
}


class RspamdAnalyzer:
    """A real spam score from a local rspamd instance (Bayes, fuzzy hashes, RBLs...)."""

    name = "rspamd"

    def __init__(self, client: RspamdClient):
        self.client = client

    async def analyze(self, email: Email) -> list[Finding]:
        if not email.raw:
            return []
        try:
            result = await self.client.check(email.raw, ip=email.sender_ip, sender=email.from_addr)
        except IntelUnavailable as exc:
            return [
                Finding(
                    signal="rspamd.unavailable",
                    points=0,
                    severity=Severity.INFO,
                    message=f"rspamd could not be reached: {exc}",
                    unavailable=True,
                )
            ]
        points, severity = _RSPAMD_ACTIONS.get(result["action"], (0, Severity.INFO))
        return [
            Finding(
                signal="spam.rspamd",
                points=points,
                severity=severity,
                message=f"rspamd spam score {result['score']:.1f} "
                f"(reject at {result['required']:.1f}): action '{result['action']}'.",
                evidence=result,
            )
        ]
