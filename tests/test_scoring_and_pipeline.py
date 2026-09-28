import asyncio
import json

import pytest
from conftest import FIXTURES, make_email
from typer.testing import CliRunner

from phishanalyzer.cli import app
from phishanalyzer.models import Finding, Level, Severity
from phishanalyzer.parsing import parse_file
from phishanalyzer.pipeline import analyze_email
from phishanalyzer.scoring import score_findings


def finding(signal: str, points: int, **kw) -> Finding:
    return Finding(signal=signal, points=points, severity=Severity.LOW, message=signal, **kw)


def test_score_is_sum_capped_at_100(settings):
    verdict = score_findings([finding("a", 60), finding("b", 70)], settings)
    assert verdict.score == 100
    assert verdict.level is Level.CRITICAL


def test_weight_override(settings):
    settings.weights = {"a": 0, "b": 45}
    verdict = score_findings([finding("a", 60), finding("b", 5)], settings)
    assert verdict.score == 45
    assert verdict.level is Level.SUSPICIOUS


def test_force_critical_overrides_low_score(settings):
    verdict = score_findings([finding("vt.malicious", 5, force_critical=True)], settings)
    assert verdict.level is Level.CRITICAL
    assert verdict.score == settings.thresholds.critical


def test_unavailable_findings_mark_partial_and_score_zero(settings):
    verdict = score_findings([finding("vt.error", 50, unavailable=True)], settings)
    assert verdict.score == 0
    assert verdict.partial


def test_findings_ordered_by_severity(settings):
    verdict = score_findings([finding("a", 5), finding("b", 20), finding("c", 0)], settings)
    assert [f.signal for f in verdict.findings] == ["b", "a", "c"]


def test_broken_analyzer_does_not_break_verdict(settings):
    class Boom:
        name = "boom"

        async def analyze(self, email):
            raise RuntimeError("kaboom")

    verdict = asyncio.run(analyze_email(make_email(), settings, [Boom()]))
    assert verdict.partial
    assert verdict.findings[0].signal == "boom.error"


def test_benign_email_is_clean(verdict_of):
    email = make_email(
        from_="Example News <news@example.com>",
        subject="Your September newsletter",
        html='<p>New articles this month. <a href="https://example.com/read">Read more</a></p>',
    )
    verdict = verdict_of(email)
    assert verdict.level is Level.CLEAN, verdict.findings


def test_classic_credential_phish_is_high_or_critical(verdict_of):
    email = make_email(
        from_="PayPal Security <alert@paypal-secure-login.com>",
        subject="Urgent: your account has been suspended",
        html='<a href="http://185.12.4.9/login">https://www.paypal.com/signin</a>',
        headers=[("Reply-To", "support@mail-help.example")],
    )
    assert verdict_of(email).level in (Level.HIGH, Level.CRITICAL)


@pytest.mark.parametrize(
    ("fixture", "allowed"),
    [
        ("test1.eml", {Level.HIGH, Level.CRITICAL}),  # Telepass brand phish
        ("test2.eml", {Level.CLEAN, Level.LOW}),  # genuine Microsoft Rewards promo
        ("test3.eml", {Level.CLEAN, Level.LOW}),  # giveaway spam, not phishing
        ("test4.eml", {Level.HIGH, Level.CRITICAL}),  # forwarded Costco prize phish
    ],
)
def test_real_fixtures(fixture, allowed, verdict_of):
    verdict = verdict_of(parse_file(FIXTURES / fixture))
    assert verdict.level in allowed, (verdict.score, [f.signal for f in verdict.findings])


def test_cli_scan_eml_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["scan-eml", str(FIXTURES / "test4.eml"), "--json"])
    assert result.exit_code == 0, result.output
    [entry] = json.loads(result.output)
    assert entry["level"] in ("high", "critical")
    assert any(f["signal"] == "headers.brand_impersonation" for f in entry["findings"])


def test_cli_scan_eml_table(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["scan-eml", str(FIXTURES / "test1.eml")])
    assert result.exit_code == 0, result.output
    assert "brand_impersonation" in result.output
