"""Parse the `Received:` chain to find where a message really came from."""

from __future__ import annotations

import re

from phishanalyzer.domains import is_ip, is_public_ip
from phishanalyzer.models import ReceivedHop

_FROM = re.compile(r"\bfrom\s+(\S+)", re.I)
_BY = re.compile(r"\bby\s+([A-Za-z0-9.\-]+)", re.I)
_PAREN = re.compile(r"\(([^()]*)\)")
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_IPV6 = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]+:[0-9a-fA-F:.]*)\]")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}\.?$")


def parse_hop(value: str) -> ReceivedHop:
    value = " ".join(value.split())
    hop = ReceivedHop()
    by = _BY.search(value)
    if by:
        hop.by_host = by.group(1).lower().rstrip(".")
    if not (frm := _FROM.search(value)):
        return hop

    hop.from_helo = frm.group(1).strip("[]").lower().rstrip(".")
    # The "from" clause runs until "by"; its parenthesised groups carry what the receiver
    # observed. Typical forms:
    #   (mta1.example.com. [203.0.113.5])   (unknown [203.0.113.5])
    #   (HELO x) ([203.0.113.5])            (example.com. 203.0.113.5)
    end = by.start() if by and by.start() > frm.end() else len(value)
    groups = _PAREN.findall(value[frm.end() : end])
    for group in groups:
        for pattern in (_IPV6, _IPV4):
            if ip := pattern.search(group):
                hop.from_ip = ip.group(1)
                break
        if hop.from_ip:
            rdns = group.split()[0] if group.split() else ""
            if _HOST.match(rdns) and not is_ip(rdns.rstrip(".")):
                hop.from_rdns = rdns.lower().rstrip(".")
            break
    if hop.from_ip is None and is_ip(hop.from_helo):
        hop.from_ip = hop.from_helo
    return hop


def parse_received(values: list[str]) -> list[ReceivedHop]:
    """Hops newest-first, i.e. in header order."""
    return [parse_hop(v) for v in values]


def origin_hop(hops: list[ReceivedHop]) -> ReceivedHop | None:
    """The hop where the recipient's server accepted the message from the outside world.

    Headers are prepended by each server, so the topmost hop with a public connecting IP
    was written by the recipient's own infrastructure and is trustworthy. Everything
    below it could have been forged by the sender.
    """
    return next((hop for hop in hops if is_public_ip(hop.from_ip)), None)
