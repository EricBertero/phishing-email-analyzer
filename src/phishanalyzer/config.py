"""Configuration: tunables from config.yaml, secrets from the environment / .env."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import AliasChoices, BaseModel, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from phishanalyzer.models import Level

DEFAULT_CONFIG_PATH = Path("config.yaml")


class SandboxUpload(StrEnum):
    NEVER = "never"
    ASK = "ask"
    ALWAYS = "always"


class Thresholds(BaseModel):
    low: int = 20
    suspicious: int = 40
    high: int = 60
    critical: int = 80

    @model_validator(mode="after")
    def _ascending(self) -> Thresholds:
        values = [self.low, self.suspicious, self.high, self.critical]
        if values != sorted(values) or len(set(values)) != len(values):
            raise ValueError(
                "thresholds must be strictly ascending: low < suspicious < high < critical"
            )
        if self.low <= 0 or self.critical > 100:
            raise ValueError("thresholds must lie within 1-100")
        return self

    def level_for(self, score: int) -> Level:
        if score >= self.critical:
            return Level.CRITICAL
        if score >= self.high:
            return Level.HIGH
        if score >= self.suspicious:
            return Level.SUSPICIOUS
        if score >= self.low:
            return Level.LOW
        return Level.CLEAN


class Paths(BaseModel):
    db: Path = Path("data/phishanalyzer.db")
    reports: Path = Path("reports")
    gmail_credentials: Path = Path("credentials.json")
    gmail_token: Path = Path("token.json")


class Dashboard(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000


class AiSummary(BaseModel):
    enabled: bool = True
    model: str = "claude-sonnet-5"


class Secrets(BaseSettings):
    """API keys. All optional: a missing key disables that integration."""

    model_config = SettingsConfigDict(
        env_prefix="PHISH_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    urlhaus_auth_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    hybrid_analysis_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    spamhaus_dqs_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("ANTHROPIC_API_KEY", "PHISH_ANTHROPIC_API_KEY"),
    )


class Settings(BaseModel):
    poll_interval_seconds: int = Field(default=60, ge=10)
    backfill_count: int = Field(default=25, ge=0)
    dry_run: bool = False
    label_prefix: str = "Phish"
    quarantine_critical: bool = False
    sandbox_upload: SandboxUpload = SandboxUpload.NEVER
    thresholds: Thresholds = Field(default_factory=Thresholds)
    vt_malicious_threshold: int = Field(default=3, ge=1)
    weights: dict[str, int] = Field(default_factory=dict)
    paths: Paths = Field(default_factory=Paths)
    dashboard: Dashboard = Field(default_factory=Dashboard)
    ai_summary: AiSummary = Field(default_factory=AiSummary)
    secrets: Secrets = Field(default_factory=Secrets, exclude=True)

    def configured_integrations(self) -> dict[str, bool]:
        """Which API-backed integrations have a key set."""
        return {
            name.removesuffix("_api_key").removesuffix("_auth_key").removesuffix("_key"): (
                value is not None and bool(value.get_secret_value())
            )
            for name, value in self.secrets
        }


def load_settings(config_path: Path | None = None, secrets: Secrets | None = None) -> Settings:
    """Load config.yaml (if present) and secrets from the environment / .env.

    An explicitly given config_path must exist; the default config.yaml is optional.
    """
    path = config_path or DEFAULT_CONFIG_PATH
    data: dict[str, Any] = {}
    if path.exists():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        if loaded is not None:
            if not isinstance(loaded, dict):
                raise ValueError(f"{path}: expected a mapping at the top level")
            data = loaded
    elif config_path is not None:
        raise FileNotFoundError(path)
    return Settings(**data, secrets=secrets if secrets is not None else Secrets())
