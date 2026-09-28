"""Decide when an email gets a report, and produce it."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from pathlib import Path

from phishanalyzer.config import Settings
from phishanalyzer.models import Email, Verdict
from phishanalyzer.reporting.ai_summary import Summarizer, SummaryResult
from phishanalyzer.reporting.render import (
    build_context,
    render_html,
    render_pdf,
    report_basename,
    write_report,
)
from phishanalyzer.storage import Report, Store

log = logging.getLogger(__name__)


def fingerprint(verdict: Verdict) -> str:
    """Identity of the evidence: same findings and points means the same report."""
    parts = sorted(
        f"{f.signal}:{f.points}:{int(f.force_critical)}"
        for f in verdict.findings
        if f.points > 0 or f.force_critical
    )
    raw = f"{verdict.level.value}|{verdict.score}|{'|'.join(parts)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class Reporter:
    def __init__(self, settings: Settings, store: Store | None, summarizer: Summarizer | None):
        self.settings = settings
        self.store = store
        self.summarizer = summarizer

    def wants(self, verdict: Verdict) -> bool:
        return verdict.level.rank >= self.settings.reports.min_level.rank

    async def maybe_report(self, provider: str, email: Email, verdict: Verdict) -> Report | None:
        """Report emails at or above `reports.min_level`, unless nothing changed."""
        if not self.wants(verdict):
            return None
        existing = self.store.get_report(provider, email.provider_id or "") if self.store else None
        if existing and existing.fingerprint == fingerprint(verdict):
            return existing
        return await self.report(provider, email, verdict)

    async def report(
        self,
        provider: str,
        email: Email,
        verdict: Verdict,
        provider_id: str | None = None,
        directory: Path | None = None,
    ) -> Report:
        provider_id = provider_id or email.provider_id or email.message_id or "message"
        result = (
            await self.summarizer.summarize(email, verdict)
            if self.summarizer
            else SummaryResult(None, "disabled")
        )
        ai_note = None if result.summary else _describe(result.status)
        html = render_html(
            build_context(email, verdict, provider, provider_id, result.summary, ai_note)
        )
        pdf = None
        if self.settings.reports.pdf:
            try:
                pdf = await asyncio.to_thread(render_pdf, html)
            except Exception:  # a PDF problem must not lose the HTML report
                log.exception("PDF rendering failed for %s", provider_id)
        html_path, pdf_path = write_report(
            directory or self.settings.paths.reports,
            report_basename(provider, provider_id),
            html,
            pdf,
        )
        report = Report(
            provider=provider,
            provider_id=provider_id,
            html_path=str(html_path.resolve()),
            pdf_path=str(pdf_path.resolve()) if pdf_path else None,
            level=verdict.level,
            score=verdict.score,
            fingerprint=fingerprint(verdict),
            ai_status=result.status,
            ai_model=result.summary.model if result.summary else None,
            ai_summary=result.summary.model_dump() if result.summary else None,
        )
        if self.store:
            report = self.store.save_report(report)
        log.info("Report written: %s", html_path)
        return report

    async def aclose(self) -> None:
        if self.summarizer:
            await self.summarizer.aclose()


def _describe(status: str) -> str | None:
    if status == "disabled":
        return "turned off in the configuration"
    if status.startswith("disabled: "):
        return status.removeprefix("disabled: ")
    if status == "declined":
        return "the model declined to summarise this email"
    return status.split(": ", 1)[-1]
