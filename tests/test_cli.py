from typer.testing import CliRunner

from phishanalyzer import __version__
from phishanalyzer.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_config_command_masks_secrets(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PHISH_VIRUSTOTAL_API_KEY", "super-secret-vt-key")
    result = runner.invoke(app, ["config"])
    assert result.exit_code == 0, result.output
    assert "super-secret-vt-key" not in result.output
    assert "virustotal: configured" in result.output
    assert "sandbox_upload: never" in result.output
