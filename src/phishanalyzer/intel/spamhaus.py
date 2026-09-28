"""Spamhaus DQS (free Data Query Service): ZEN for IPs and DBL for domains, over DNS.

DQS needs a free key and works from any resolver. The public mirrors refuse queries
that come through large public resolvers such as 8.8.8.8.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from phishanalyzer.intel.base import IntelCache, IntelUnavailable

ZEN_CODES = {
    "127.0.0.2": "SBL (spam source)",
    "127.0.0.3": "CSS (snowshoe spam)",
    "127.0.0.4": "XBL (exploited/infected host)",
    "127.0.0.5": "XBL (exploited/infected host)",
    "127.0.0.6": "XBL (exploited/infected host)",
    "127.0.0.7": "XBL (exploited/infected host)",
    "127.0.0.9": "DROP (hijacked network)",
    "127.0.0.10": "PBL (dynamic/end-user IP)",
    "127.0.0.11": "PBL (dynamic/end-user IP)",
}
POLICY_ONLY = {"127.0.0.10", "127.0.0.11"}

DBL_CODES = {
    "127.0.1.2": "spam",
    "127.0.1.4": "phishing",
    "127.0.1.5": "malware",
    "127.0.1.6": "botnet C&C",
    "127.0.1.102": "abused legit (spam)",
    "127.0.1.103": "abused legit (spammed redirector)",
    "127.0.1.104": "abused legit (phishing)",
    "127.0.1.105": "abused legit (malware)",
    "127.0.1.106": "abused legit (botnet C&C)",
}
DBL_DANGEROUS = {"127.0.1.4", "127.0.1.5", "127.0.1.6"}
DBL_ABUSED_LEGIT = {"127.0.1.102", "127.0.1.103", "127.0.1.104", "127.0.1.105", "127.0.1.106"}

Resolve = Callable[[str], Awaitable[list[str]]]


async def dns_resolve(qname: str) -> list[str]:
    """A records for `qname`, or [] when not listed (NXDOMAIN)."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = await resolver.resolve(qname, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise IntelUnavailable(f"spamhaus: DNS error: {exc}") from exc
    return [record.to_text() for record in answer]


class SpamhausClient:
    service = "spamhaus"

    def __init__(
        self,
        cache: IntelCache,
        dqs_key: str,
        resolve: Resolve = dns_resolve,
        cache_seconds: float = 12 * 3600,
    ):
        self.cache = cache
        self.key = dqs_key
        self.resolve = resolve
        self.cache_seconds = cache_seconds

    async def _lookup(self, kind: str, name: str, zone: str) -> list[str]:
        cache_key = f"spamhaus:{kind}:{name}"
        hit = self.cache.get(cache_key)
        if hit is not None:
            return hit["v"]
        codes = await self.resolve(f"{name}.{self.key}.{zone}.dq.spamhaus.net")
        # 127.255.255.x are error codes (bad key, over quota...), never listings.
        if any(code.startswith("127.255.255.") for code in codes):
            raise IntelUnavailable(f"spamhaus: query refused ({', '.join(codes)})")
        self.cache.set(cache_key, {"v": codes}, self.cache_seconds)
        return codes

    async def ip(self, ip: str) -> dict[str, Any]:
        """{codes, reasons, policy_only} for an IPv4 address (IPv6 is not queried)."""
        if ipaddress.ip_address(ip).version != 4:
            return {"codes": [], "reasons": [], "policy_only": False}
        reversed_ip = ".".join(reversed(ip.split(".")))
        codes = await self._lookup("ip", reversed_ip, "zen")
        return {
            "codes": codes,
            "reasons": sorted({ZEN_CODES.get(c, c) for c in codes}),
            "policy_only": bool(codes) and set(codes) <= POLICY_ONLY,
        }

    async def domain(self, domain: str) -> dict[str, Any]:
        """{codes, reasons, dangerous, abused_legit} for a registrable domain."""
        codes = await self._lookup("domain", domain.lower(), "dbl")
        return {
            "codes": codes,
            "reasons": sorted({DBL_CODES.get(c, c) for c in codes}),
            "dangerous": any(c in DBL_DANGEROUS for c in codes),
            "abused_legit": bool(codes) and set(codes) <= DBL_ABUSED_LEGIT,
        }
