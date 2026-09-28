"""Command-line entry point: `phish ...`."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from phishanalyzer import __version__
from phishanalyzer.analyzers import build_analyzers
from phishanalyzer.config import Settings, load_settings
from phishanalyzer.intel import Intel
from phishanalyzer.models import Level
from phishanalyzer.parsing import parse_file
from phishanalyzer.pipeline import analyze_email
from phishanalyzer.providers import AuthRequired
from phishanalyzer.sandbox_worker import SandboxWorker
from phishanalyzer.scanner import Scanner
from phishanalyzer.storage import ACTIVE_JOB_STATUSES, JobStatus, Store

app = typer.Typer(help="Phishing Email Analyzer", no_args_is_help=True)

ConfigOption = Annotated[
    Path | None, typer.Option("--config", "-c", help="Path to config.yaml", exists=True)
]


def _version(value: bool) -> None:
    if value:
        typer.echo(f"phishanalyzer {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version")
    ] = False,
) -> None:
    """Phishing Email Analyzer."""
    # Email subjects are full of emoji and exotic characters; a Windows console or a
    # pipe with a legacy code page must print '?' for them, never crash.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


_LEVEL_STYLE = {
    Level.CLEAN: "green",
    Level.LOW: "cyan",
    Level.SUSPICIOUS: "yellow",
    Level.HIGH: "red",
    Level.CRITICAL: "bold white on red",
}


@app.command("scan-eml")
def scan_eml(
    files: Annotated[
        list[Path], typer.Argument(help=".eml files to analyse", exists=True, dir_okay=False)
    ],
    config_path: ConfigOption = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print verdicts as JSON")] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Also show passed/informational checks")
    ] = False,
    offline: Annotated[
        bool,
        typer.Option("--offline", help="Skip threat-intel lookups: nothing leaves this machine"),
    ] = False,
) -> None:
    """Analyse local .eml files and print the score breakdown.

    Configured threat-intel services are queried with the email's indicators (URLs,
    domains, IPs, attachment hashes) unless --offline is given.
    """
    settings = load_settings(config_path)
    console = Console()
    results = asyncio.run(_scan_files(files, settings, offline))

    if as_json:
        payload = [
            {
                "file": str(path),
                "subject": email.subject,
                "from": email.from_addr,
                **verdict.model_dump(mode="json"),
            }
            for path, email, verdict in results
        ]
        typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    for path, email, verdict in results:
        style = _LEVEL_STYLE[verdict.level]
        console.rule(f"[bold]{path.name}")
        console.print(f"[dim]From:[/]    {email.from_display or ''} <{email.from_addr}>")
        if email.forwarded:
            console.print(
                f"[dim]Orig.:[/]   {email.forwarded.from_display or ''} "
                f"<{email.forwarded.from_addr}> (forwarded)"
            )
        console.print(f"[dim]Subject:[/] {email.subject}")
        console.print(
            f"[dim]Verdict:[/] [{style}] {verdict.level.upper()} [/] score {verdict.score}/100"
            + ("  [yellow](partial: some checks unavailable)[/]" if verdict.partial else "")
        )
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        table.add_column("pts", justify="right")
        table.add_column("signal")
        table.add_column("why")
        for f in verdict.findings:
            if f.points == 0 and not f.force_critical and not verbose:
                continue
            table.add_row(
                "!" if f.force_critical else str(f.points),
                f.signal,
                f.message,
                style=("dim" if f.points == 0 else None),
            )
        console.print(table)


def _setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )
    # Google's client logs every discovery/cache detail at INFO.
    logging.getLogger("googleapiclient").setLevel(logging.WARNING)


def _gmail(settings, interactive: bool = False):
    from phishanalyzer.providers.gmail import GmailProvider

    try:
        return GmailProvider.from_settings(settings, interactive=interactive)
    except AuthRequired as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1) from exc


async def _scan_files(files: list[Path], settings: Settings, offline: bool):
    intel = None if offline else Intel(settings)
    analyzers = build_analyzers(settings, intel)
    try:
        results = []
        for path in files:
            email = parse_file(path)
            results.append((path, email, await analyze_email(email, settings, analyzers)))
        return results
    finally:
        if intel:
            await intel.aclose()


@app.command()
def auth(config_path: ConfigOption = None) -> None:
    """Authorise access to your Gmail account (opens a browser window)."""
    settings = load_settings(config_path)
    provider = _gmail(settings, interactive=True)
    typer.echo(f"Authorised as {provider.account()}; token saved to {settings.paths.gmail_token}")


@app.command()
def run(
    config_path: ConfigOption = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Analyse and log, but never modify Gmail")
    ] = False,
    once: Annotated[bool, typer.Option("--once", help="Poll a single time and exit")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Watch the inbox: scan new mail as it arrives and label it with its verdict."""
    _setup_logging(verbose)
    settings = load_settings(config_path)
    if dry_run:
        settings.dry_run = True
    provider = _gmail(settings)
    store = Store(settings.paths.db)
    log = logging.getLogger("phishanalyzer")
    log.info(
        "Watching %s every %ds%s",
        provider.account(),
        settings.poll_interval_seconds,
        " (dry run: Gmail will not be modified)" if settings.dry_run else "",
    )

    async def main() -> None:
        intel = Intel(settings, cache=store.intel_cache())
        log.info("Threat intel: %s", ", ".join(intel.enabled) or "none configured (offline)")
        analyzers = build_analyzers(settings, intel, store, provider.name)
        scanner = Scanner(settings, provider, store, analyzers)
        worker = (
            SandboxWorker(settings, provider, store, intel.hybrid_analysis, scanner)
            if intel.hybrid_analysis
            else None
        )
        if worker:
            log.info("Sandbox: uploads %s", settings.sandbox_upload.value)
        try:
            if once:
                result = await scanner.poll_once()
                log.info(
                    "Scanned %d, skipped %d, failed %d, re-checked %d",
                    result.scanned,
                    result.skipped,
                    result.failed,
                    result.rechecked,
                )
                if worker:
                    sandbox = await worker.run_once()
                    log.info(
                        "Sandbox: %d submitted, %d finished, %d failed, %d re-scored",
                        sandbox.submitted,
                        sandbox.finished,
                        sandbox.failed,
                        sandbox.rescored,
                    )
            else:
                await _run_until_stopped(scanner, worker)
        finally:
            await intel.aclose()

    try:
        asyncio.run(main())
    except AuthRequired as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1) from exc
    except KeyboardInterrupt:
        log.info("Stopped")


async def _run_until_stopped(scanner: Scanner, worker: SandboxWorker | None) -> None:
    """Run the mailbox poller and the sandbox worker side by side.

    If one of them dies (e.g. Gmail access was revoked), stop the other and re-raise.
    """
    stop = asyncio.Event()
    tasks = [asyncio.create_task(scanner.run_forever(stop))]
    if worker:
        tasks.append(asyncio.create_task(worker.run_forever(stop)))
    try:
        await asyncio.gather(*tasks)
    finally:
        stop.set()
        await asyncio.gather(*tasks, return_exceptions=True)


sandbox_app = typer.Typer(help="Review and approve attachment uploads to the sandbox.")
app.add_typer(sandbox_app, name="sandbox")


@sandbox_app.command("list")
def sandbox_list(
    config_path: ConfigOption = None,
    all_jobs: Annotated[bool, typer.Option("--all", help="Include finished jobs")] = False,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 50,
) -> None:
    """List sandbox jobs (by default only those still open)."""
    settings = load_settings(config_path)
    store = Store(settings.paths.db)
    jobs = store.jobs(statuses=None if all_jobs else ACTIVE_JOB_STATUSES, limit=limit)
    if not jobs:
        typer.echo("No sandbox jobs." if all_jobs else "No open sandbox jobs.")
        return
    table = Table(box=None, header_style="bold")
    for column in ("id", "status", "file", "size", "verdict", "from", "subject"):
        table.add_column(column)
    for job in jobs:
        row = store.get_row(job.provider, job.provider_id)
        table.add_row(
            str(job.id),
            job.status.value,
            job.filename or job.sha256[:12],
            f"{job.size / 1024:.0f} KB",
            f"{job.verdict} ({job.threat_score})" if job.verdict else "",
            (row.from_addr or "") if row else "",
            ((row.subject or "")[:50]) if row else "",
        )
    Console().print(table)
    waiting = sum(1 for j in jobs if j.status is JobStatus.AWAITING_APPROVAL)
    if waiting:
        typer.echo()
        typer.echo(
            f"{waiting} awaiting approval. Uploading makes a file visible to other users "
            "of the sandbox service."
        )
        typer.echo("Approve with `phish sandbox approve <id>` or `--all`; decline with reject.")


def _decide(approve: bool, ids: list[int] | None, all_jobs: bool, config_path: Path | None) -> None:
    if not ids and not all_jobs:
        typer.secho("Give job ids, or --all.", fg="red", err=True)
        raise typer.Exit(2)
    store = Store(load_settings(config_path).paths.db)
    count = store.decide_jobs(approve, None if all_jobs else ids)
    verb = "Approved" if approve else "Rejected"
    typer.echo(f"{verb} {count} job(s).")
    if approve and count:
        typer.echo("The running `phish run` will upload them within a poll interval.")


@sandbox_app.command("approve")
def sandbox_approve(
    ids: Annotated[
        list[int] | None, typer.Argument(help="Job ids from `phish sandbox list`")
    ] = None,
    all_jobs: Annotated[bool, typer.Option("--all")] = False,
    config_path: ConfigOption = None,
) -> None:
    """Allow the listed files to be uploaded to Hybrid Analysis."""
    _decide(True, ids, all_jobs, config_path)


@sandbox_app.command("reject")
def sandbox_reject(
    ids: Annotated[
        list[int] | None, typer.Argument(help="Job ids from `phish sandbox list`")
    ] = None,
    all_jobs: Annotated[bool, typer.Option("--all")] = False,
    config_path: ConfigOption = None,
) -> None:
    """Decline the upload of the listed files."""
    _decide(False, ids, all_jobs, config_path)


@app.command()
def recent(
    config_path: ConfigOption = None,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 20,
    level: Annotated[Level | None, typer.Option("--level", case_sensitive=False)] = None,
) -> None:
    """List the most recently scanned emails."""
    settings = load_settings(config_path)
    rows = Store(settings.paths.db).recent(limit=limit, level=level)
    table = Table(box=None, header_style="bold")
    for column in ("scanned (UTC)", "level", "score", "from", "subject"):
        table.add_column(column)
    for row in rows:
        lvl = Level(row.level) if row.level else None
        table.add_row(
            row.scanned_at.strftime("%Y-%m-%d %H:%M"),
            f"[{_LEVEL_STYLE[lvl]}]{lvl.value}[/]" if lvl else "[red]error[/]",
            "" if row.score is None else str(row.score),
            row.from_addr or "",
            (row.subject or row.error or "")[:70],
        )
    Console().print(table if rows else "No scanned emails yet. Run `phish run` first.")


@app.command()
def doctor(config_path: ConfigOption = None) -> None:
    """Check that each configured threat-intel service is reachable and its key works."""
    from phishanalyzer.intel.doctor import run_checks

    settings = load_settings(config_path)

    async def main():
        intel = Intel(settings)
        try:
            return intel.enabled, await run_checks(intel)
        finally:
            await intel.aclose()

    enabled, results = asyncio.run(main())
    if not enabled:
        typer.echo("No threat-intel services configured. Add API keys to .env (see .env.example).")
        return
    for result in results:
        mark = "[green]OK  [/]" if result.ok else "[red]FAIL[/]"
        Console().print(f"{mark} {result.service}: {result.detail}")
    missing = [n for n, on in settings.configured_integrations().items() if not on]
    if missing:
        typer.echo(f"Not configured: {', '.join(missing)}")
    if not all(r.ok for r in results):
        raise typer.Exit(1)


@app.command()
def config(config_path: ConfigOption = None) -> None:
    """Show the effective configuration and which integrations have API keys."""
    settings = load_settings(config_path)
    typer.echo(yaml.safe_dump(settings.model_dump(mode="json"), sort_keys=False).rstrip())
    typer.echo("\nintegrations:")
    for name, configured in settings.configured_integrations().items():
        typer.echo(f"  {name}: {'configured' if configured else 'not configured (disabled)'}")
