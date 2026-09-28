"""Raw RFC 822 bytes -> `Email`. One parser for every provider and for local .eml files."""

from __future__ import annotations

import contextlib
import hashlib
from email import message_from_bytes, policy
from email.message import EmailMessage, Message
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path

from phishanalyzer.models import Attachment, Email
from phishanalyzer.parsing.forwarded import parse_forwarded
from phishanalyzer.parsing.received import origin_hop, parse_received
from phishanalyzer.parsing.urls import extract_urls, html_to_text


def _header_items(msg: Message) -> list[tuple[str, str]]:
    items = []
    for name, value in msg.raw_items():
        try:
            text = str(msg.policy.header_fetch_parse(name, value))
        except Exception:  # malformed header: keep the raw text rather than dropping it
            text = str(value)
        items.append((name, " ".join(text.split())))
    return items


def _decode_text(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except Exception:
        # Unknown or lying charset: decode bytes leniently instead of losing the body.
        payload = part.get_payload(decode=True) or b""
        try:
            return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")


def _is_attachment(part: EmailMessage) -> bool:
    if part.is_multipart():
        return False
    return part.get_content_disposition() == "attachment" or bool(part.get_filename())


def _addr(value: str | None) -> str | None:
    if not value:
        return None
    return parseaddr(value)[1].strip("<>").lower() or None


def parse_message(raw: bytes, provider_id: str | None = None) -> Email:
    msg: EmailMessage = message_from_bytes(raw, policy=policy.default)  # type: ignore[assignment]
    headers = _header_items(msg)
    email = Email(provider_id=provider_id, headers=headers, raw=raw)

    email.message_id = (email.header("Message-ID") or "").strip() or None
    email.subject = email.header("Subject") or ""
    display, addr = parseaddr(email.header("From") or "")
    email.from_display = display or None
    email.from_addr = addr.lower() or None
    email.reply_to = _addr(email.header("Reply-To"))
    email.return_path = _addr(email.header("Return-Path"))
    email.to = [a.lower() for _, a in getaddresses(email.header_all("To")) if a]
    if date := email.header("Date"):
        with contextlib.suppress(TypeError, ValueError):
            email.date = parsedate_to_datetime(date)

    text_parts, html_parts = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if _is_attachment(part):
            data = part.get_payload(decode=True) or b""
            email.attachments.append(
                Attachment(
                    filename=part.get_filename(),
                    content_type=part.get_content_type(),
                    size=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                    data=data,
                )
            )
        elif part.get_content_type() == "text/plain":
            text_parts.append(_decode_text(part))
        elif part.get_content_type() == "text/html":
            html_parts.append(_decode_text(part))
    email.text_body = "\n".join(text_parts)
    email.html_body = "\n".join(html_parts)
    email.urls = extract_urls(email.text_body, email.html_body)

    email.received = parse_received(email.header_all("Received"))
    if origin := origin_hop(email.received):
        email.sender_ip = origin.from_ip
        email.sender_rdns = origin.from_rdns

    email.forwarded = parse_forwarded(email.text_body or html_to_text(email.html_body))
    return email


def parse_file(path: Path) -> Email:
    return parse_message(path.read_bytes())
