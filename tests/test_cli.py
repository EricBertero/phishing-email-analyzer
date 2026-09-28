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


def test_doctor_without_keys(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "No threat-intel services configured" in result.output


def test_config_lists_rspamd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("intel:\n  rspamd_url: http://localhost:11333\n")
    result = runner.invoke(app, ["config"])
    assert "rspamd: configured" in result.output


def test_scan_eml_offline_flag(tmp_path, monkeypatch):
    from conftest import FIXTURES

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PHISH_URLHAUS_AUTH_KEY", "would-hit-the-network")
    result = runner.invoke(app, ["scan-eml", str(FIXTURES / "test3.eml"), "--offline", "--json"])
    assert result.exit_code == 0, result.output
    assert "urlhaus" not in result.output


def test_scan_eml_survives_legacy_console_encoding(tmp_path):
    """Emoji subjects must not crash on a cp1252 console or pipe (Windows default)."""
    import os
    import subprocess
    import sys

    from conftest import FIXTURES

    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from phishanalyzer.cli import app; app()",
            "scan-eml",
            str(FIXTURES / "test3.eml"),
            "--offline",
        ],
        capture_output=True,
        cwd=tmp_path,
        env=env,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode("cp1252", "replace")
    assert b"Giveaways" in result.stdout
