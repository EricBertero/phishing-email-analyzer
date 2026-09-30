"""Render a verdict to a self-contained HTML report and (optionally) a PDF."""

from __future__ import annotations

import io
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from phishanalyzer import __version__
from phishanalyzer.domains import domain_of_address, hostname_of_url, registrable_domain
from phishanalyzer.models import Email, Level, Verdict
from phishanalyzer.reporting.ai_summary import AiSummary
from phishanalyzer.reporting.redact import defang

MAX_URLS = 25
# Long tracking URLs can't wrap inside PDF table cells; the host is what matters.
MAX_URL_CHARS = 90

_env = Environment(
    loader=PackageLoader("phishanalyzer.reporting", "templates"),
    # Every value may come from an attacker (subject, display name, AI output derived
    # from the email): escape everything.
    autoescape=select_autoescape(default=True, default_for_string=True),
    trim_blocks=True,
    lstrip_blocks=True,
)

_LEVEL_LABEL = {
    Level.CLEAN: "CLEAN",
    Level.LOW: "LOW RISK",
    Level.SUSPICIOUS: "SUSPICIOUS",
    Level.HIGH: "HIGH RISK",
    Level.CRITICAL: "CRITICAL",
}


def default_actions(verdict: Verdict) -> list[str]:
    """Rule-based advice, used when there is no AI summary."""
    signals = {f.signal for f in verdict.findings if f.points > 0 or f.force_critical}
    if verdict.level.rank <= Level.LOW.rank:
        return [
            "No action needed. If something about this email feels wrong, verify with the "
            "sender through a channel you already know."
        ]
    actions = ["Do not click links, open attachments or reply to this email."]
    if any(s.startswith("attachments.") for s in signals):
        actions.append(
            "If you opened an attachment, disconnect from the network and run a "
            "full antivirus scan."
        )
    if any("brand" in s or "lookalike" in s or "credential" in s for s in signals):
        actions.append(
            "If you need to check your account, open the company's website or app "
            "yourself instead of using the email."
        )
    actions.append(
        "If you already entered a password, change it now and enable two-factor authentication."
    )
    actions.append("Report the email as phishing in Gmail, then delete it.")
    return actions


def fallback_summary(verdict: Verdict) -> str:
    top = [f.message for f in verdict.findings if f.points > 0 or f.force_critical][:3]
    if not top:
        return "No significant warning signs were found."
    return "Main reasons: " + " ".join(top)


def build_context(
    email: Email,
    verdict: Verdict,
    provider: str,
    provider_id: str,
    ai: AiSummary | None,
    ai_note: str | None,
) -> dict[str, Any]:
    scored = [f for f in verdict.findings if f.points > 0 or f.force_critical]
    info = [f for f in verdict.findings if not (f.points > 0 or f.force_critical)]
    urls = [_shorten(defang(u.url)) for u in email.urls if u.source != "form" and u.url]
    hosts = {hostname_of_url(u.url) for u in email.urls if u.url}
    domains = {
        registrable_domain(h)
        for h in (
            *hosts,
            domain_of_address(email.from_addr),
            domain_of_address(email.reply_to),
            domain_of_address(email.return_path),
            domain_of_address(email.forwarded.from_addr) if email.forwarded else None,
        )
        if h
    }
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "version": __version__,
        "provider": provider,
        "provider_id": provider_id,
        "level": verdict.level.value,
        "level_label": _LEVEL_LABEL[verdict.level],
        "score": verdict.score,
        "partial": verdict.partial,
        "subject": email.subject,
        "from_display": email.from_display,
        "from_addr": defang(email.from_addr or ""),
        "forwarded_from": defang(email.forwarded.from_addr or "") if email.forwarded else None,
        "reply_to": defang(email.reply_to) if email.reply_to else None,
        "return_path": defang(email.return_path) if email.return_path else None,
        "to": ", ".join(email.to),
        "sent_at": email.date.strftime("%Y-%m-%d %H:%M %Z").strip() if email.date else None,
        "message_id": email.message_id,
        "sender_ip": email.sender_ip,
        "sender_ip_defanged": defang(email.sender_ip or ""),
        "sender_rdns": email.sender_rdns,
        "ai": ai,
        "ai_note": ai_note,
        "fallback_summary": fallback_summary(verdict),
        "actions": ai.recommended_actions
        if ai and ai.recommended_actions
        else default_actions(verdict),
        "findings": scored,
        "info_findings": [f for f in info if not f.unavailable][:12],
        "ioc_domains": sorted(defang(d) for d in domains if d),
        "urls": urls[:MAX_URLS],
        "urls_truncated": max(0, len(urls) - MAX_URLS),
        "attachments": [
            {
                "filename": a.filename,
                "content_type": a.content_type,
                "size_kb": max(1, round(a.size / 1024)),
                "sha256": a.sha256,
            }
            for a in email.attachments
        ],
        "auth": email.header("Authentication-Results"),
        "hops": email.received[:8],
    }


def _shorten(url: str) -> str:
    return url if len(url) <= MAX_URL_CHARS else url[: MAX_URL_CHARS - 1] + "…"


def render_html(context: dict[str, Any]) -> str:
    return _env.get_template("report.html.j2").render(**context)


SCREEN_FONTS_START = "/* screen-fonts:start */"
SCREEN_FONTS_END = "/* screen-fonts:end */"


def without_screen_fonts(html: str) -> str:
    """Drop the template's web-font block: xhtml2pdf would try to fetch the dashboard's
    /static URLs, which don't exist on disk. The PDF uses Helvetica instead."""
    start = html.find(SCREEN_FONTS_START)
    end = html.find(SCREEN_FONTS_END)
    if start == -1 or end < start:
        return html
    return html[:start] + html[end + len(SCREEN_FONTS_END) :]


def render_pdf(html: str) -> bytes:
    import logging

    from xhtml2pdf import pisa  # heavy import, only when a PDF is wanted

    # xhtml2pdf warns about every CSS property it can't render (the browser-only ones
    # in the shared template); that is expected and just noise in the CLI.
    logging.getLogger("xhtml2pdf").setLevel(logging.ERROR)

    buffer = io.BytesIO()
    result = pisa.CreatePDF(without_screen_fonts(html), dest=buffer, encoding="utf-8")
    if result.err:
        raise RuntimeError(f"PDF rendering failed ({result.err} errors)")
    return buffer.getvalue()


def report_basename(provider: str, provider_id: str) -> str:
    """Stable, filesystem-safe name, so a regenerated report replaces the old one."""
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", provider_id).strip("_")[:80] or "message"
    return f"{provider}-{safe}"


def write_report(
    directory: Path, basename: str, html: str, pdf: bytes | None
) -> tuple[Path, Path | None]:
    directory.mkdir(parents=True, exist_ok=True)
    html_path = directory / f"{basename}.html"
    html_path.write_text(html, encoding="utf-8")
    pdf_path = None
    if pdf is not None:
        pdf_path = directory / f"{basename}.pdf"
        pdf_path.write_bytes(pdf)
    return html_path, pdf_path
