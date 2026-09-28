"""Hostname / domain helpers shared by the parser and analyzers."""

from __future__ import annotations

import ipaddress
import re
from functools import cache
from urllib.parse import urlsplit

import tldextract

# Offline: use the Public Suffix List snapshot bundled with tldextract, never fetch it.
# Private suffixes (e.g. us.com, web.app) count, so `x.digitalfluxzone.us.com` resolves to
# `digitalfluxzone.us.com` instead of `us.com`.
_extract = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


def domain_of_address(address: str | None) -> str | None:
    """`Name <user@Example.com>` / `user@example.com` -> `example.com`."""
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip(" >").lower() or None


def hostname_of_url(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def is_ip(host: str | None) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value.strip("[]")).is_global
    except ValueError:
        return False


@cache
def registrable_domain(host: str | None) -> str | None:
    """Organisational domain (eTLD+1): `a.b.mail.example.co.uk` -> `example.co.uk`."""
    if not host:
        return None
    host = host.lower().rstrip(".")
    if is_ip(host):
        return host
    parts = _extract(host)
    if not parts.domain:
        return host
    if not parts.suffix:
        # TLD not on the Public Suffix List (brand-new TLD, internal name): treat the
        # last two labels as the organisation instead of collapsing to a bare label.
        return ".".join(host.split(".")[-2:])
    return f"{parts.domain}.{parts.suffix}"


def domain_label(host: str | None) -> str | None:
    """Registrable domain without its suffix: `mail.paypal.co.uk` -> `paypal`."""
    if not host or is_ip(host):
        return None
    return _extract(host.lower()).domain or None


def same_org(a: str | None, b: str | None) -> bool:
    return bool(a and b) and registrable_domain(a) == registrable_domain(b)


def looks_random(label: str) -> bool:
    """Heuristic for machine-generated names like `mzpffvewq` or `svbudsbhgyufdvghdfk`.

    Real words (in English and Italian) almost never have 6+ consonants in a row;
    "strengths" has 5. `y` counts as a vowel so "rhythms" is not flagged.
    """
    letters = re.sub(r"[^a-z]", "", label.lower())
    if len(letters) < 8:
        return False
    longest_run = max((len(run) for run in re.findall(r"[^aeiouy]+", letters)), default=0)
    return longest_run >= 6


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]
