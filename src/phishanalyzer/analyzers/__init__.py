from __future__ import annotations

from typing import TYPE_CHECKING

from phishanalyzer.analyzers.attachments import AttachmentAnalyzer
from phishanalyzer.analyzers.auth import AuthAnalyzer
from phishanalyzer.analyzers.base import Analyzer
from phishanalyzer.analyzers.content import ContentAnalyzer
from phishanalyzer.analyzers.headers import HeaderAnalyzer
from phishanalyzer.analyzers.intel import (
    AbuseIpdbAnalyzer,
    SpamhausAnalyzer,
    UrlhausAnalyzer,
    VirusTotalAnalyzer,
)
from phishanalyzer.analyzers.spam import RspamdAnalyzer, SpamHeaderAnalyzer
from phishanalyzer.analyzers.urls import UrlAnalyzer

if TYPE_CHECKING:
    from phishanalyzer.config import Settings
    from phishanalyzer.intel import Intel


def offline_analyzers() -> list[Analyzer]:
    """Checks that need no network access or API keys."""
    return [
        AuthAnalyzer(),
        HeaderAnalyzer(),
        SpamHeaderAnalyzer(),
        ContentAnalyzer(),
        UrlAnalyzer(),
        AttachmentAnalyzer(),
    ]


def build_analyzers(settings: Settings, intel: Intel | None) -> list[Analyzer]:
    """Offline checks plus every threat-intel check whose service is configured."""
    analyzers = offline_analyzers()
    if intel is None:
        return analyzers
    if intel.urlhaus:
        analyzers.append(UrlhausAnalyzer(intel.urlhaus, settings))
    if intel.spamhaus:
        analyzers.append(SpamhausAnalyzer(intel.spamhaus, settings))
    if intel.abuseipdb:
        analyzers.append(AbuseIpdbAnalyzer(intel.abuseipdb))
    if intel.virustotal:
        analyzers.append(VirusTotalAnalyzer(intel.virustotal, settings))
    if intel.rspamd:
        analyzers.append(RspamdAnalyzer(intel.rspamd))
    return analyzers


__all__ = [
    "AbuseIpdbAnalyzer",
    "Analyzer",
    "AttachmentAnalyzer",
    "AuthAnalyzer",
    "ContentAnalyzer",
    "HeaderAnalyzer",
    "RspamdAnalyzer",
    "SpamHeaderAnalyzer",
    "SpamhausAnalyzer",
    "UrlAnalyzer",
    "UrlhausAnalyzer",
    "VirusTotalAnalyzer",
    "build_analyzers",
    "offline_analyzers",
]
