"""Core data types shared by the parser, analyzers, scoring, storage and UI."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Level(StrEnum):
    """Overall verdict for an email, derived from its score."""

    CLEAN = "clean"
    LOW = "low"
    SUSPICIOUS = "suspicious"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """0 (clean) .. 4 (critical), for comparisons like `level.rank >= other.rank`."""
        return list(Level).index(self)


class Attachment(BaseModel):
    filename: str | None
    content_type: str
    size: int
    sha256: str
    # Raw bytes are needed by the analyzers and sandbox upload, but never serialised.
    data: bytes = Field(default=b"", exclude=True, repr=False)


class Url(BaseModel):
    url: str
    # Visible anchor text when the URL came from an HTML link; used to spot mismatches.
    display_text: str | None = None
    source: str = "text"  # "text" | "html" (link href) | "form" (form action)


class ReceivedHop(BaseModel):
    """One `Received:` header: the relay `from_*` handed the message to `by_host`."""

    from_helo: str | None = None  # name the sender announced (unverified)
    from_rdns: str | None = None  # reverse DNS of the connecting IP, as seen by the receiver
    from_ip: str | None = None
    by_host: str | None = None


class ForwardedHeader(BaseModel):
    """Original sender block of a forwarded message (`---------- Forwarded message ---`)."""

    from_display: str | None = None
    from_addr: str | None = None
    subject: str | None = None


class Email(BaseModel):
    """A parsed email, independent of the mail provider it came from."""

    provider_id: str | None = None  # e.g. Gmail message id; None for local .eml files
    message_id: str | None = None
    subject: str = ""
    from_addr: str | None = None
    from_display: str | None = None
    reply_to: str | None = None
    return_path: str | None = None
    to: list[str] = Field(default_factory=list)
    date: datetime | None = None
    headers: list[tuple[str, str]] = Field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    urls: list[Url] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    received: list[ReceivedHop] = Field(default_factory=list)  # newest (top) first
    # Public IP that handed the message to the recipient's mail server: the only hop in
    # the Received chain that is not under the sender's control.
    sender_ip: str | None = None
    sender_rdns: str | None = None
    forwarded: ForwardedHeader | None = None
    # Original RFC 822 bytes, for checks that need the whole message (rspamd).
    raw: bytes = Field(default=b"", exclude=True, repr=False)

    def header(self, name: str) -> str | None:
        """First value of a header (case-insensitive), or None."""
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), None)

    def header_all(self, name: str) -> list[str]:
        """All values of a header (case-insensitive), in message order."""
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]


class Finding(BaseModel):
    """One piece of evidence produced by an analyzer."""

    signal: str  # stable id, e.g. "auth.dmarc_fail"; used for weight overrides
    points: int
    severity: Severity
    message: str  # human-readable explanation shown in the dashboard and report
    evidence: dict[str, Any] = Field(default_factory=dict)
    # A known-malicious indicator (e.g. VT-flagged attachment) that makes the email Critical
    # regardless of its total score.
    force_critical: bool = False
    # The check could not run (missing key, API down, rate-limited); scored as 0 points.
    unavailable: bool = False


class Verdict(BaseModel):
    score: int  # 0-100
    level: Level
    findings: list[Finding]
    # True when some checks were unavailable, so the email should be re-checked later.
    partial: bool = False
