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


def _sandbox_config(tmp_path):
    from phishanalyzer.storage import JobStatus, Store

    db = tmp_path / "test.db"
    (tmp_path / "config.yaml").write_text(f"paths:\n  db: {db.as_posix()}\n")
    store = Store(db)
    for i, name in enumerate(["invoice.pdf", "scan.doc"], start=1):
        store.enqueue_job("gmail", f"m{i}", f"sha{i}", name, 2048, JobStatus.AWAITING_APPROVAL)
    return store


def test_sandbox_list_approve_and_reject(tmp_path, monkeypatch):
    from phishanalyzer.storage import JobStatus

    monkeypatch.chdir(tmp_path)
    store = _sandbox_config(tmp_path)

    listed = runner.invoke(app, ["sandbox", "list"])
    assert listed.exit_code == 0, listed.output
    assert "invoice.pdf" in listed.output and "awaiting_approval" in listed.output
    assert "2 awaiting approval" in listed.output

    approved = runner.invoke(app, ["sandbox", "approve", "1"])
    assert "Approved 1 job(s)" in approved.output
    assert store.get_job(1).status is JobStatus.PENDING
    assert store.get_job(2).status is JobStatus.AWAITING_APPROVAL

    rejected = runner.invoke(app, ["sandbox", "reject", "--all"])
    assert "Rejected 1 job(s)" in rejected.output
    assert store.get_job(2).status is JobStatus.REJECTED
    assert store.get_job(1).status is JobStatus.PENDING  # already approved: untouched


def test_sandbox_decision_needs_ids_or_all(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _sandbox_config(tmp_path)
    result = runner.invoke(app, ["sandbox", "approve"])
    assert result.exit_code == 2


def test_sandbox_list_empty(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert "No open sandbox jobs" in runner.invoke(app, ["sandbox", "list"]).output


def test_run_until_stopped_stops_worker_when_scanner_dies():
    import asyncio

    from phishanalyzer.cli import _run_until_stopped
    from phishanalyzer.providers import AuthRequired

    events = []

    class Scanner:
        async def run_forever(self, stop):
            await asyncio.sleep(0.01)
            raise AuthRequired("token revoked")

    class Worker:
        async def run_forever(self, stop):
            await stop.wait()  # only ends when told to stop
            events.append("worker stopped")

    import pytest

    with pytest.raises(AuthRequired, match="token revoked"):
        asyncio.run(_run_until_stopped(Scanner(), Worker()))
    assert events == ["worker stopped"]


def test_scan_eml_report_offline(tmp_path, monkeypatch):
    from conftest import FIXTURES

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-be-used-offline")
    result = runner.invoke(app, ["scan-eml", str(FIXTURES / "test1.eml"), "--report", "--offline"])
    assert result.exit_code == 0, result.output
    html = (tmp_path / "reports" / "file-test1.html").read_text(encoding="utf-8")
    assert "CRITICAL" in html and "hxxps://storage[.]googleapis[.]com" in html
    assert "AI summary not included" in html  # --offline: nothing sent to Claude
    assert (tmp_path / "reports" / "file-test1.pdf").read_bytes().startswith(b"%PDF")


def test_supervisor_stops_everything_when_dashboard_ends():
    import asyncio

    from phishanalyzer.cli import _run_until_stopped

    stopped = []

    class Scanner:
        async def run_forever(self, stop):
            await stop.wait()
            stopped.append("scanner")

    class Worker:
        async def run_forever(self, stop):
            await stop.wait()
            stopped.append("worker")

    async def dashboard(stop):
        await asyncio.sleep(0.01)  # e.g. uvicorn exiting on Ctrl+C

    asyncio.run(_run_until_stopped(Scanner(), Worker(), dashboard))
    assert sorted(stopped) == ["scanner", "worker"]


def test_serve_refuses_non_loopback_host(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("dashboard:\n  host: 0.0.0.0\n")
    result = runner.invoke(app, ["serve"])
    assert result.exit_code == 2 and "Refusing" in result.output


def test_dashboard_port_in_use_is_a_clear_error(settings):
    import asyncio
    import socket

    import pytest
    from fastapi import FastAPI

    from phishanalyzer.cli import _dashboard_runner

    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        port = blocker.getsockname()[1]
        with pytest.raises(RuntimeError, match="port in use"):
            asyncio.run(_dashboard_runner(FastAPI(), settings, port)(asyncio.Event()))
