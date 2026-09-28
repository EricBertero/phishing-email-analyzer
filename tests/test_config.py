from pathlib import Path

import pytest
from pydantic import ValidationError

from phishanalyzer.config import SandboxUpload, Secrets, Thresholds, load_settings
from phishanalyzer.models import Level

EXAMPLE_CONFIG = Path(__file__).parent.parent / "config.example.yaml"


def no_secrets() -> Secrets:
    return Secrets(_env_file=None)


def test_defaults_without_config_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    settings = load_settings(secrets=no_secrets())
    assert settings.sandbox_upload is SandboxUpload.NEVER
    assert settings.dry_run is False
    assert settings.dashboard.host == "127.0.0.1"


def test_example_config_matches_defaults(tmp_path, monkeypatch):
    """config.example.yaml documents the defaults, so it must not drift from them."""
    example = load_settings(EXAMPLE_CONFIG, secrets=no_secrets())
    monkeypatch.chdir(tmp_path)
    defaults = load_settings(secrets=no_secrets())
    assert example.model_dump() == defaults.model_dump()


def test_yaml_overrides(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("dry_run: true\nthresholds: {critical: 90}\nweights: {auth.dmarc_fail: 30}\n")
    settings = load_settings(cfg, secrets=no_secrets())
    assert settings.dry_run is True
    assert settings.thresholds.critical == 90
    assert settings.weights == {"auth.dmarc_fail": 30}


def test_explicit_missing_config_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_settings(tmp_path / "nope.yaml", secrets=no_secrets())


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (0, Level.CLEAN),
        (19, Level.CLEAN),
        (20, Level.LOW),
        (40, Level.SUSPICIOUS),
        (60, Level.HIGH),
        (79, Level.HIGH),
        (80, Level.CRITICAL),
        (100, Level.CRITICAL),
    ],
)
def test_level_for(score, level):
    assert Thresholds().level_for(score) is level


@pytest.mark.parametrize(
    "bad", [{"low": 50, "suspicious": 40}, {"high": 40}, {"low": 0}, {"critical": 101}]
)
def test_invalid_thresholds(bad):
    with pytest.raises(ValidationError):
        Thresholds(**bad)


def test_secrets_from_env(monkeypatch):
    monkeypatch.setenv("PHISH_VIRUSTOTAL_API_KEY", "vt-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    secrets = Secrets(_env_file=None)
    assert secrets.virustotal_api_key.get_secret_value() == "vt-key"
    assert secrets.anthropic_api_key.get_secret_value() == "sk-test"


def test_configured_integrations(monkeypatch):
    for var in ("PHISH_VIRUSTOTAL_API_KEY", "PHISH_URLHAUS_AUTH_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PHISH_URLHAUS_AUTH_KEY", "abc")
    settings = load_settings(EXAMPLE_CONFIG, secrets=Secrets(_env_file=None))
    integrations = settings.configured_integrations()
    assert integrations["urlhaus"] is True
    assert integrations["virustotal"] is False


def test_secrets_never_serialised(monkeypatch):
    monkeypatch.setenv("PHISH_VIRUSTOTAL_API_KEY", "vt-key")
    settings = load_settings(EXAMPLE_CONFIG, secrets=Secrets(_env_file=None))
    assert "vt-key" not in str(settings.model_dump(mode="json"))
