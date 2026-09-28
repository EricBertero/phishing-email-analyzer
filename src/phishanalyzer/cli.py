"""Command-line entry point: `phish ...`."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
import yaml

from phishanalyzer import __version__
from phishanalyzer.config import load_settings

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


@app.command()
def config(config_path: ConfigOption = None) -> None:
    """Show the effective configuration and which integrations have API keys."""
    settings = load_settings(config_path)
    typer.echo(yaml.safe_dump(settings.model_dump(mode="json"), sort_keys=False).rstrip())
    typer.echo("\nintegrations:")
    for name, configured in settings.configured_integrations().items():
        typer.echo(f"  {name}: {'configured' if configured else 'missing key (disabled)'}")
