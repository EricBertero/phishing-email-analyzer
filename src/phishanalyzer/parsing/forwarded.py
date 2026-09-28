"""Recover the original sender from a forwarded email's body.

Users often forward suspicious mail to themselves or to a security mailbox; the outer
headers then describe the forwarder, and the interesting sender only exists as text.
"""

from __future__ import annotations

import re
from email.utils import parseaddr

from phishanalyzer.models import ForwardedHeader

# Gmail: "---------- Forwarded message ---------", Outlook: "-----Original Message-----",
# Apple Mail: "Begin forwarded message:", Italian Gmail: "Messaggio inoltrato".
_MARKER = re.compile(
    r"-{2,}\s*(?:Forwarded message|Original Message|Messaggio inoltrato|Messaggio originale)"
    r"\s*-{2,}|Begin forwarded message:|Inizio messaggio inoltrato:",
    re.I,
)
_FIELD = re.compile(r"^\s*[>*]*\s*(From|Da|Subject|Oggetto)\s*:\s*(.+?)\s*$", re.I | re.M)


def parse_forwarded(text: str) -> ForwardedHeader | None:
    marker = _MARKER.search(text or "")
    if not marker:
        return None
    # The header block is the first handful of lines after the marker.
    block = "\n".join(text[marker.end() :].strip().splitlines()[:10])
    info = ForwardedHeader()
    for name, value in _FIELD.findall(block):
        name = name.lower()
        if name in ("from", "da") and info.from_addr is None:
            display, addr = parseaddr(value.replace("*", ""))
            info.from_display = display or None
            info.from_addr = addr.lower() or None
        elif name in ("subject", "oggetto") and info.subject is None:
            info.subject = value
    return info if info.from_addr else None
