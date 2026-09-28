from __future__ import annotations

import asyncio
from email.message import EmailMessage
from pathlib import Path

import pytest

from phishanalyzer.config import Secrets, Settings
from phishanalyzer.models import Email, Finding, Verdict
from phishanalyzer.parsing import parse_message
from phishanalyzer.pipeline import analyze_email

FIXTURES = Path(__file__).parent / "fixtures" / "eml"

GOOD_AUTH = (
    "mx.google.com; dkim=pass header.i=@example.com header.s=s1; "
    "spf=pass (google.com: domain of bounce@example.com designates 52.10.20.30 as permitted "
    "sender) smtp.mailfrom=bounce@example.com; dmarc=pass (p=REJECT) header.from=example.com"
)
GOOD_RECEIVED = (
    "from mail.example.com (mail.example.com. [52.10.20.30]) by mx.google.com with ESMTPS "
    "id abc; Mon, 1 Sep 2025 10:00:00 -0700 (PDT)"
)


def build_eml(
    *,
    from_: str = "Example News <news@example.com>",
    to: str = "me@gmail.com",
    subject: str = "Hello",
    text: str | None = "Hi there,\nSee you soon.",
    html: str | None = None,
    headers: list[tuple[str, str]] | None = None,
    attachments: list[tuple[str, bytes]] | None = None,
    authenticated: bool = True,
) -> bytes:
    """A syntactically real email; by default a well-authenticated, harmless one."""
    msg = EmailMessage()
    if authenticated:
        msg["Received"] = GOOD_RECEIVED
        msg["Authentication-Results"] = GOOD_AUTH
    for name, value in headers or []:
        msg[name] = value
    msg["From"] = from_
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = "Mon, 01 Sep 2025 17:00:00 +0000"
    msg["Message-ID"] = "<abc123@example.com>"
    if text is not None:
        msg.set_content(text)
    if html is not None:
        if text is None:
            msg.set_content(html, subtype="html")
        else:
            msg.add_alternative(html, subtype="html")
    for filename, data in attachments or []:
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=filename)
    return msg.as_bytes()


def make_email(**kwargs) -> Email:
    return parse_message(build_eml(**kwargs))


def run(analyzer, email: Email) -> list[Finding]:
    return asyncio.run(analyzer.analyze(email))


def signals(findings: list[Finding]) -> set[str]:
    return {f.signal for f in findings if f.points > 0 or f.force_critical}


@pytest.fixture(autouse=True)
def _no_real_api_keys(monkeypatch):
    """Tests must never hit real services with a developer's keys from the environment."""
    import os

    for var in list(os.environ):
        if var.startswith("PHISH_") or var == "ANTHROPIC_API_KEY":
            monkeypatch.delenv(var)


@pytest.fixture
def settings() -> Settings:
    return Settings(secrets=Secrets(_env_file=None))


@pytest.fixture
def verdict_of(settings):
    def _verdict(email: Email) -> Verdict:
        return asyncio.run(analyze_email(email, settings))

    return _verdict
