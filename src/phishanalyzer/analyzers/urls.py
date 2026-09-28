"""Static link checks. Links are never fetched: only their text is inspected."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from phishanalyzer.domains import (
    domain_of_address,
    hostname_of_url,
    is_ip,
    registrable_domain,
    same_org,
)
from phishanalyzer.models import Email, Finding, Severity, Url

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "v.gd", "shorturl.com",
}  # fmt: skip

# Free hosting that phishers use to put a landing page on a reputable domain.
# Matched against the full hostname (suffix match).
ABUSED_HOSTING = (
    "storage.googleapis.com", "firebasestorage.googleapis.com", "web.app", "firebaseapp.com",
    "blob.core.windows.net", "r2.dev", "pages.dev", "workers.dev", "webflow.io", "weebly.com",
    "wixsite.com", "glitch.me", "netlify.app", "vercel.app", "github.io", "ipfs.io",
    "dweb.link", "ipfs.dweb.link", "sites.google.com", "forms.gle", "000webhostapp.com",
    "square.site", "godaddysites.com", "blogspot.com", "herokuapp.com", "repl.co",
)  # fmt: skip

# Anchor text that itself looks like a link or domain, e.g. "www.paypal.com".
_URLISH_TEXT = re.compile(
    r"^(?:https?://)?(?:www\.)?([a-z0-9\-]+(?:\.[a-z0-9\-]+)+)(?:/\S*)?$", re.I
)


def _on_abused_hosting(host: str) -> bool:
    return any(host == h or host.endswith("." + h) for h in ABUSED_HOSTING)


class UrlAnalyzer:
    name = "urls"

    async def analyze(self, email: Email) -> list[Finding]:
        links = [u for u in email.urls if u.source != "form" and hostname_of_url(u.url)]
        sender_orgs = {
            registrable_domain(domain_of_address(addr))
            for addr in (email.from_addr, email.forwarded and email.forwarded.from_addr)
            if addr
        }
        findings: list[Finding] = []
        findings += self._mismatched_text(links, sender_orgs)
        findings += self._host_checks(links)
        return findings

    def _mismatched_text(self, links: list[Url], sender_orgs: set[str | None]) -> list[Finding]:
        mismatches = []
        for link in links:
            if link.source != "html" or not link.display_text:
                continue
            shown = _URLISH_TEXT.match(link.display_text.strip())
            if not shown:
                continue
            shown_host, real_host = shown.group(1).lower(), hostname_of_url(link.url)
            # Links through the sender's own click tracker are normal in newsletters; a
            # phisher can't route victims through the impersonated company's domain.
            if registrable_domain(real_host) in sender_orgs:
                continue
            if "." in shown_host and not same_org(shown_host, real_host):
                mismatches.append({"shown": link.display_text.strip(), "actual": link.url})
        if not mismatches:
            return []
        return [
            Finding(
                signal="urls.text_mismatch",
                points=20,
                severity=Severity.HIGH,
                message=f"A link displays {mismatches[0]['shown']} but actually points to "
                f"{hostname_of_url(mismatches[0]['actual'])}.",
                evidence={"links": mismatches[:5]},
            )
        ]

    def _host_checks(self, links: list[Url]) -> list[Finding]:
        ip_links, short, hosted, puny, userinfo = [], set(), set(), set(), []
        for link in links:
            host = hostname_of_url(link.url) or ""
            if is_ip(host):
                ip_links.append(link.url)
            if registrable_domain(host) in SHORTENERS or host in SHORTENERS:
                short.add(host)
            if _on_abused_hosting(host):
                hosted.add(host)
            if host.startswith("xn--") or ".xn--" in host:
                puny.add(host)
            if "@" in (urlsplit(link.url).netloc or ""):
                userinfo.append(link.url)

        findings = []
        if ip_links:
            findings.append(
                Finding(
                    signal="urls.ip_address",
                    points=15,
                    severity=Severity.MEDIUM,
                    message="A link points to a raw IP address instead of a domain name.",
                    evidence={"urls": ip_links[:5]},
                )
            )
        if hosted:
            findings.append(
                Finding(
                    signal="urls.abused_hosting",
                    points=15,
                    severity=Severity.MEDIUM,
                    message="Links lead to free cloud hosting often used for phishing pages "
                    f"({', '.join(sorted(hosted))}).",
                    evidence={"hosts": sorted(hosted)},
                )
            )
        if short:
            findings.append(
                Finding(
                    signal="urls.shortener",
                    points=5,
                    severity=Severity.LOW,
                    message=f"Links are hidden behind URL shorteners ({', '.join(sorted(short))}).",
                    evidence={"hosts": sorted(short)},
                )
            )
        if puny:
            findings.append(
                Finding(
                    signal="urls.punycode",
                    points=15,
                    severity=Severity.MEDIUM,
                    message="Links use punycode domains, which can imitate real ones.",
                    evidence={"hosts": sorted(puny)},
                )
            )
        if userinfo:
            findings.append(
                Finding(
                    signal="urls.userinfo",
                    points=15,
                    severity=Severity.MEDIUM,
                    message="A link hides its real destination after an '@' "
                    "(e.g. https://paypal.com@evil.example).",
                    evidence={"urls": userinfo[:5]},
                )
            )
        return findings
