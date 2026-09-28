from phishanalyzer.analyzers.attachments import AttachmentAnalyzer
from phishanalyzer.analyzers.auth import AuthAnalyzer
from phishanalyzer.analyzers.base import Analyzer
from phishanalyzer.analyzers.content import ContentAnalyzer
from phishanalyzer.analyzers.headers import HeaderAnalyzer
from phishanalyzer.analyzers.spam import SpamHeaderAnalyzer
from phishanalyzer.analyzers.urls import UrlAnalyzer


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


__all__ = [
    "Analyzer",
    "AttachmentAnalyzer",
    "AuthAnalyzer",
    "ContentAnalyzer",
    "HeaderAnalyzer",
    "SpamHeaderAnalyzer",
    "UrlAnalyzer",
    "offline_analyzers",
]
