"""Local web dashboard: overview, scanned emails, sandbox approvals, reports, uploads."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import mimetypes
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from phishanalyzer import __version__
from phishanalyzer.analyzers import Analyzer, offline_analyzers
from phishanalyzer.config import Settings
from phishanalyzer.models import Level
from phishanalyzer.parsing import parse_message
from phishanalyzer.pipeline import analyze_email
from phishanalyzer.providers import AuthRequired, MessageGone, ProviderError
from phishanalyzer.reporting.reporter import Reporter
from phishanalyzer.scanner import Scanner
from phishanalyzer.storage import JobStatus, Store
from phishanalyzer.web.security import (
    REPORT_CSP,
    LocalOnlyMiddleware,
    csrf_ok,
    new_csrf_token,
)
from phishanalyzer.web.stats import build_overview

log = logging.getLogger(__name__)

HERE = Path(__file__).parent
# Windows' registry often lacks woff2, so the bundled Geist fonts would go out as
# application/octet-stream. Register the proper type once.
mimetypes.add_type("font/woff2", ".woff2")
PAGE_SIZE = 50
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

# Notices are chosen from this fixed set by key; free text from the URL is never shown.
NOTICES = {
    "rescanned": ("ok", "The email was analysed again."),
    "reported": ("ok", "The report was written."),
    "approved": ("ok", "Approved. `phish run` uploads it within one poll interval."),
    "rejected": ("ok", "Upload declined."),
    "none": ("info", "Nothing was waiting for approval."),
    "gone": ("error", "The message no longer exists in the mailbox."),
    "mailbox": ("error", "The mailbox could not be reached. Try again later."),
    "auth": ("error", "Gmail access expired. Run `phish auth` and restart."),
    "no-mailbox": ("error", "Not connected to Gmail. Start the dashboard with `phish run`."),
    "no-raw": ("error", "Uploaded files are not kept, so they can't be re-analysed."),
    "bad-csrf": ("error", "The form expired. Reload the page and try again."),
}

LEVEL_LABELS = {
    Level.CLEAN.value: "Clean",
    Level.LOW.value: "Low",
    Level.SUSPICIOUS.value: "Suspicious",
    Level.HIGH.value: "High",
    Level.CRITICAL.value: "Critical",
}


@dataclass
class Services:
    settings: Settings
    store: Store
    upload_analyzers: list[Analyzer]
    reporter: Reporter | None = None
    # Present when the dashboard runs inside `phish run` (or `serve` with Gmail access).
    scanner: Scanner | None = None
    csrf_token: str = ""

    def __post_init__(self) -> None:
        self.csrf_token = self.csrf_token or new_csrf_token()


def _ago(value: datetime | None) -> str:
    if value is None:
        return ""
    value = value if value.tzinfo else value.replace(tzinfo=UTC)
    seconds = (datetime.now(UTC) - value).total_seconds()
    if seconds < 90:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)} h ago"
    if seconds < 7 * 86400:
        return f"{int(seconds // 86400)} d ago"
    return value.strftime("%d %b %Y")


def _stamp(value: datetime | None) -> str:
    if value is None:
        return ""
    value = value if value.tzinfo else value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _filesize(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.0f} KB"
    return f"{size / 1024 / 1024:.1f} MB"


def _asset_version() -> str:
    """Content hash of the static files: browsers refetch them exactly when they change."""
    digest = hashlib.sha256()
    for path in sorted((HERE / "static").rglob("*")):
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()[:10]


def create_app(services: Services) -> FastAPI:
    app = FastAPI(title="Phishing Email Analyzer", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(LocalOnlyMiddleware)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.filters["ago"] = _ago
    templates.env.filters["stamp"] = _stamp
    templates.env.filters["filesize"] = _filesize
    templates.env.globals.update(
        version=__version__,
        asset_version=_asset_version(),
        level_labels=LEVEL_LABELS,
        levels=[lv.value for lv in Level],
    )
    store = services.store

    def page(request: Request, name: str, **context) -> HTMLResponse:
        notice = NOTICES.get(request.query_params.get("notice", ""))
        return templates.TemplateResponse(
            request,
            name,
            {
                "csrf": services.csrf_token,
                "notice": notice,
                "has_mailbox": services.scanner is not None,
                "awaiting": store.count_jobs(JobStatus.AWAITING_APPROVAL),
                **context,
            },
        )

    def back(path: str, notice: str) -> RedirectResponse:
        return RedirectResponse(f"{path}?{urlencode({'notice': notice})}", status_code=303)

    def check_csrf(token: str | None) -> bool:
        return csrf_ok(services.csrf_token, token)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request):
        return page(request, "overview.html", nav="overview", o=build_overview(store))

    @app.get("/emails", response_class=HTMLResponse)
    def emails(request: Request, level: str | None = None, q: str | None = None, p: int = 1):
        selected = Level(level) if level in LEVEL_LABELS else None
        p = max(1, p)
        rows, total = store.search(selected, q, offset=(p - 1) * PAGE_SIZE, limit=PAGE_SIZE)
        pages = max(1, -(-total // PAGE_SIZE))

        def link(**changes) -> str:
            params = {"level": selected.value if selected else None, "q": q or None, "p": p}
            params.update(changes)
            return "/emails?" + urlencode({k: v for k, v in params.items() if v not in (None, 1)})

        return page(
            request,
            "emails.html",
            nav="emails",
            rows=rows,
            total=total,
            level=selected.value if selected else None,
            q=q or "",
            p=p,
            pages=pages,
            link=link,
        )

    @app.get("/emails/{row_id}", response_class=HTMLResponse)
    def email_detail(request: Request, row_id: int):
        row = store.get_row_by_id(row_id)
        if row is None:
            raise HTTPException(404, "No such email")
        scored = [f for f in row.findings if f.get("points", 0) > 0 or f.get("force_critical")]
        other = [f for f in row.findings if f not in scored]
        return page(
            request,
            "email.html",
            nav="emails",
            row=row,
            scored=scored,
            other=other,
            report=store.get_report(row.provider, row.provider_id),
            jobs=store.jobs_for_message(row.provider, row.provider_id),
            can_rescan=services.scanner is not None
            and row.provider == services.scanner.provider.name,
        )

    async def _reanalyse(row_id: int, write_report: bool) -> str:
        row = store.get_row_by_id(row_id)
        if row is None:
            raise HTTPException(404, "No such email")
        if row.provider == "upload":
            return "no-raw"
        scanner = services.scanner
        if scanner is None or row.provider != scanner.provider.name:
            return "no-mailbox"
        try:
            if write_report and services.reporter:
                # Same as `phish report`: re-analyse once, store, report whatever the level.
                raw = await asyncio.to_thread(scanner.provider.get_raw, row.provider_id)
                email = parse_message(raw, provider_id=row.provider_id)
                verdict = await analyze_email(email, services.settings, scanner.analyzers)
                store.save_result(row.provider, email, verdict, rechecks=row.rechecks)
                await services.reporter.report(row.provider, email, verdict)
            else:
                await scanner.scan_message(row.provider_id, rechecks=row.rechecks)
        except MessageGone:
            return "gone"
        except AuthRequired:
            return "auth"
        except ProviderError:
            return "mailbox"
        return "reported" if write_report else "rescanned"

    @app.post("/emails/{row_id}/rescan")
    async def rescan(row_id: int, csrf: Annotated[str | None, Form()] = None):
        if not check_csrf(csrf):
            return back(f"/emails/{row_id}", "bad-csrf")
        return back(f"/emails/{row_id}", await _reanalyse(row_id, write_report=False))

    @app.post("/emails/{row_id}/report")
    async def make_report(row_id: int, csrf: Annotated[str | None, Form()] = None):
        if not check_csrf(csrf):
            return back(f"/emails/{row_id}", "bad-csrf")
        return back(f"/emails/{row_id}", await _reanalyse(row_id, write_report=True))

    @app.get("/sandbox", response_class=HTMLResponse)
    def sandbox(request: Request, show: str = "open"):
        statuses = (
            None
            if show == "all"
            else (JobStatus.AWAITING_APPROVAL, JobStatus.PENDING, JobStatus.SUBMITTED)
        )
        jobs = store.jobs(statuses=statuses, limit=200)
        rows = {(j.provider, j.provider_id): store.get_row(j.provider, j.provider_id) for j in jobs}
        return page(
            request,
            "sandbox.html",
            nav="sandbox",
            jobs=list(reversed(jobs)),
            rows=rows,
            show=show,
            upload_mode=services.settings.sandbox_upload.value,
        )

    @app.post("/sandbox/decide")
    def decide(
        action: Annotated[str, Form()],
        csrf: Annotated[str | None, Form()] = None,
        job_id: Annotated[int | None, Form()] = None,
        next_path: Annotated[str, Form(alias="next")] = "/sandbox",
    ):
        target = next_path if next_path.startswith("/") and not next_path.startswith("//") else "/"
        if not check_csrf(csrf):
            return back(target, "bad-csrf")
        if action not in ("approve", "reject"):
            raise HTTPException(400, "Unknown action")
        count = store.decide_jobs(action == "approve", None if job_id is None else [job_id])
        if count == 0:
            return back(target, "none")
        return back(target, "approved" if action == "approve" else "rejected")

    @app.get("/upload", response_class=HTMLResponse)
    def upload_form(request: Request):
        return page(
            request,
            "upload.html",
            nav="upload",
            intel_enabled=len(services.upload_analyzers) > len(offline_analyzers()),
            error=None,
        )

    @app.post("/upload", response_class=HTMLResponse)
    async def upload(
        request: Request,
        file: Annotated[UploadFile, File()],
        csrf: Annotated[str | None, Form()] = None,
        offline: Annotated[bool, Form()] = False,
        report: Annotated[bool, Form()] = False,
    ):
        def fail(message: str, status: int = 400) -> HTMLResponse:
            response = page(request, "upload.html", nav="upload", intel_enabled=True, error=message)
            response.status_code = status
            return response

        if not check_csrf(csrf):
            return fail("The form expired. Reload the page and try again.", 403)
        raw = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            return fail("That file is larger than 25 MB.", 413)
        if not raw.strip():
            return fail("That file is empty.")
        provider_id = hashlib.sha256(raw).hexdigest()[:16]
        email = parse_message(raw, provider_id=provider_id)
        known = {"from", "to", "subject", "date", "message-id", "received"}
        if not any(name.lower() in known for name, _ in email.headers):
            return fail("That doesn't look like an email (.eml) file.")
        analyzers = offline_analyzers() if offline else services.upload_analyzers
        verdict = await analyze_email(email, services.settings, analyzers)
        row = store.save_result("upload", email, verdict)
        if report and services.reporter:
            await services.reporter.report("upload", email, verdict)
        return RedirectResponse(f"/emails/{row.id}", status_code=303)

    def _report_file(report_id: int, pdf: bool) -> Path:
        report = store.get_report_by_id(report_id)
        raw_path = (report.pdf_path if pdf else report.html_path) if report else None
        if not raw_path:
            raise HTTPException(404, "No such report")
        path = Path(raw_path).resolve()
        reports_dir = services.settings.paths.reports.resolve()
        if not path.is_relative_to(reports_dir) or not path.is_file():
            raise HTTPException(404, "Report file not found")
        return path

    @app.get("/reports/{report_id}")
    def report_html(report_id: int) -> Response:
        path = _report_file(report_id, pdf=False)
        return FileResponse(
            path, media_type="text/html", headers={"Content-Security-Policy": REPORT_CSP}
        )

    @app.get("/reports/{report_id}/pdf")
    def report_pdf(report_id: int) -> Response:
        path = _report_file(report_id, pdf=True)
        return FileResponse(
            path,
            media_type="application/pdf",
            headers={"Content-Disposition": f'inline; filename="{path.name}"'},
        )

    return app
