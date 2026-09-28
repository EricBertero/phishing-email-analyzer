"""Run every analyzer on an email and score the result."""

from __future__ import annotations

import asyncio
import logging

from phishanalyzer.analyzers import Analyzer, offline_analyzers
from phishanalyzer.config import Settings
from phishanalyzer.models import Email, Finding, Severity, Verdict
from phishanalyzer.scoring import score_findings

log = logging.getLogger(__name__)


async def _run(analyzer: Analyzer, email: Email) -> list[Finding]:
    try:
        return await analyzer.analyze(email)
    except Exception as exc:  # one broken check must never lose the whole verdict
        log.exception("analyzer %s failed on %s", analyzer.name, email.message_id)
        return [
            Finding(
                signal=f"{analyzer.name}.error",
                points=0,
                severity=Severity.INFO,
                message=f"The {analyzer.name} check failed: {exc}",
                unavailable=True,
            )
        ]


async def analyze_email(
    email: Email, settings: Settings, analyzers: list[Analyzer] | None = None
) -> Verdict:
    analyzers = analyzers if analyzers is not None else offline_analyzers()
    results = await asyncio.gather(*(_run(a, email) for a in analyzers))
    return score_findings([f for findings in results for f in findings], settings)
