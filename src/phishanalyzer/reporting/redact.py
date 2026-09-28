"""Make indicators safe to display and message text safe to share.

* Defanging: `https://evil.com/x` -> `hxxps://evil[.]com/x`, so a report can never be
  clicked through to a live phishing page (standard practice in incident reports).
* Redaction: personal data an attacker's message tends to contain (the recipient's
  address, phone numbers, account numbers, one-time codes) is masked before any excerpt
  leaves the machine.
"""

from __future__ import annotations

import re

_SCHEME = re.compile(r"^(h)tt(ps?)(://)", re.I)
_EMAIL = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
_URL = re.compile(r"(?:https?|ftp)://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
_CARD = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_PHONE = re.compile(r"(?<![\w])\+?\d[\d \-().]{7,}\d(?![\w])")
_LONG_NUMBER = re.compile(r"\b\d{6,}\b")


def defang(value: str) -> str:
    """Neutralise a URL, hostname or address for display."""
    value = _SCHEME.sub(lambda m: f"{m.group(1)}xx{m.group(2)}{m.group(3)}", value)
    return (
        value.replace(".", "[.]").replace("@", "[@]") if "://" not in value else _defang_url(value)
    )


def _defang_url(url: str) -> str:
    scheme, _, rest = url.partition("://")
    host, sep, path = rest.partition("/")
    return f"{scheme}://{host.replace('.', '[.]')}{sep}{path}"


def redact(text: str) -> str:
    """Mask personal data and replace links with their defanged host only."""

    def link(match: re.Match[str]) -> str:
        url = match.group(0)
        host = re.sub(r"^(?:https?|ftp)://", "", url, flags=re.I).split("/")[0].split("?")[0]
        return f"[link to {host.replace('.', '[.]')}]"

    text = _URL.sub(link, text)
    text = _EMAIL.sub("[email]", text)
    text = _IBAN.sub("[account number]", text)
    text = _CARD.sub("[number]", text)
    text = _PHONE.sub("[phone]", text)
    return _LONG_NUMBER.sub("[number]", text)


def excerpt(text: str, max_chars: int) -> str:
    """Redacted, whitespace-normalised start of a message body."""
    if max_chars <= 0:
        return ""
    lines = [" ".join(line.split()) for line in text.splitlines()]
    compact = "\n".join(line for line in lines if line)
    redacted = redact(compact)
    return redacted if len(redacted) <= max_chars else redacted[:max_chars].rstrip() + " [...]"
