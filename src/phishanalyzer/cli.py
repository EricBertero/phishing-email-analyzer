"""Command-line entry point: `phish ...`."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import astuple
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from phishanalyzer import __version__
from phishanalyzer.config import load_settings
from phishanalyzer.models import Level
from phishanalyzer.parsing import parse_file
from phishanalyzer.pipeline import analyze_email
from phishanalyzer.providers import AuthRequired
from phishanalyzer.scanner import Scanner
from phishanalyzer.storage import Store

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
) -> None:
    """Analyse local .eml files and print the score breakdown. Nothing is sent anywhere."""
    settings = load_settings(config_path)
    console = Console()
    results = []
    for path in files:
        email = parse_file(path)
        verdict = asyncio.run(analyze_email(email, settings))
        results.append((path, email, verdict))

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
    scanner = Scanner(settings, provider, store)
    log = logging.getLogger("phishanalyzer")
    log.info(
        "Watching %s every %ds%s",
        provider.account(),
        settings.poll_interval_seconds,
        " (dry run: Gmail will not be modified)" if settings.dry_run else "",
    )
    try:
        if once:
            result = asyncio.run(scanner.poll_once())
            log.info("Scanned %d, skipped %d, failed %d", *astuple(result)[:3])
        else:
            asyncio.run(scanner.run_forever())
    except AuthRequired as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1) from exc
    except KeyboardInterrupt:
        log.info("Stopped")


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
def config(config_path: ConfigOption = None) -> None:
    """Show the effective configuration and which integrations have API keys."""
    settings = load_settings(config_path)
    typer.echo(yaml.safe_dump(settings.model_dump(mode="json"), sort_keys=False).rstrip())
    typer.echo("\nintegrations:")
    for name, configured in settings.configured_integrations().items():
        typer.echo(f"  {name}: {'configured' if configured else 'missing key (disabled)'}")
