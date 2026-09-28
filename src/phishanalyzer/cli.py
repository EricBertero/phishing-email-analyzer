"""Command-line entry point: `phish ...`."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console
from rich.table import Table

from phishanalyzer import __version__
from phishanalyzer.config import load_settings
from phishanalyzer.models import Level
from phishanalyzer.parsing import parse_file
from phishanalyzer.pipeline import analyze_email

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


@app.command()
def config(config_path: ConfigOption = None) -> None:
    """Show the effective configuration and which integrations have API keys."""
    settings = load_settings(config_path)
    typer.echo(yaml.safe_dump(settings.model_dump(mode="json"), sort_keys=False).rstrip())
    typer.echo("\nintegrations:")
    for name, configured in settings.configured_integrations().items():
        typer.echo(f"  {name}: {'configured' if configured else 'missing key (disabled)'}")
