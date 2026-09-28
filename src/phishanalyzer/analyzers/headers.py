"""Sender identity checks: spoofed display names, lookalike domains, mismatched addresses."""

from __future__ import annotations

import re
from functools import cache
from importlib.resources import files

import yaml

from phishanalyzer.domains import (
    domain_label,
    domain_of_address,
    levenshtein,
    looks_random,
    registrable_domain,
    same_org,
)
from phishanalyzer.models import Email, Finding, Severity

# TLDs that are cheap/free and dominate phishing statistics (Spamhaus, Interisle reports).
SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "rest", "zip", "mov", "buzz", "icu", "cfd", "sbs", "monster",
    "cyou", "lol", "quest", "bond", "gq", "tk", "ml", "cf", "ga", "work", "support",
}  # fmt: skip

# Reverse-DNS patterns of consumer / dynamic IP space; real mail servers are not on these.
_DYNAMIC_RDNS = re.compile(
    r"(?:^|[.\-])(?:res|dyn|dynamic|dhcp|dsl|adsl|cable|pool|ppp|client|broadband|"
    r"customer|home|cpe)(?:[.\-]|\d)|\d{1,3}[.\-]\d{1,3}[.\-]\d{1,3}[.\-]\d{1,3}",
    re.I,
)
_EMAIL_IN_TEXT = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")


@cache
def load_brands() -> dict[str, frozenset[str]]:
    text = files("phishanalyzer.data").joinpath("brands.yaml").read_text(encoding="utf-8-sig")
    return {brand.lower(): frozenset(domains) for brand, domains in yaml.safe_load(text).items()}


def _brand_in(display: str, brand: str) -> bool:
    # Whole-word match, treating punctuation as separators: "Your-Costco Gift" -> costco.
    normalised = " " + re.sub(r"[^a-z0-9]+", " ", display.lower()) + " "
    return f" {brand} " in normalised


def _is_official(domain: str, official: frozenset[str]) -> bool:
    return registrable_domain(domain) in official


class HeaderAnalyzer:
    name = "headers"

    def __init__(self, brands: dict[str, frozenset[str]] | None = None):
        self.brands = brands if brands is not None else load_brands()

    async def analyze(self, email: Email) -> list[Finding]:
        findings: list[Finding] = []
        senders = [("sender", email.from_display, email.from_addr)]
        if email.forwarded:
            findings.append(
                Finding(
                    signal="headers.forwarded",
                    points=0,
                    severity=Severity.INFO,
                    message="Forwarded message: the original sender was also analysed.",
                    evidence={"original_from": email.forwarded.from_addr},
                )
            )
            senders.append(
                ("original sender", email.forwarded.from_display, email.forwarded.from_addr)
            )

        for role, display, addr in senders:
            findings += self._sender_identity(role, display, addr)

        from_domain = domain_of_address(email.from_addr)
        reply_domain = domain_of_address(email.reply_to)
        if from_domain and reply_domain and not same_org(from_domain, reply_domain):
            findings.append(
                Finding(
                    signal="headers.reply_to_mismatch",
                    points=15,
                    severity=Severity.MEDIUM,
                    message=f"Replies go to {email.reply_to}, a different organisation "
                    f"from the sender ({email.from_addr}).",
                    evidence={"from": email.from_addr, "reply_to": email.reply_to},
                )
            )
        rp_domain = domain_of_address(email.return_path)
        if from_domain and rp_domain and not same_org(from_domain, rp_domain):
            # Normal for newsletters sent through an ESP, so only a weak signal.
            findings.append(
                Finding(
                    signal="headers.return_path_mismatch",
                    points=3,
                    severity=Severity.INFO,
                    message=f"Bounces go to {rp_domain}, not the From domain {from_domain}.",
                    evidence={"return_path": email.return_path},
                )
            )

        if email.sender_rdns and _DYNAMIC_RDNS.search(email.sender_rdns):
            findings.append(
                Finding(
                    signal="headers.dynamic_ip",
                    points=10,
                    severity=Severity.MEDIUM,
                    message=f"Sent from a residential/dynamic IP ({email.sender_ip}, "
                    f"{email.sender_rdns}), not a real mail server.",
                    evidence={"ip": email.sender_ip, "rdns": email.sender_rdns},
                )
            )
        if email.received and not email.message_id:
            findings.append(
                Finding(
                    signal="headers.missing_message_id",
                    points=5,
                    severity=Severity.LOW,
                    message="No Message-ID header; legitimate mail servers always add one.",
                )
            )
        return findings

    def _sender_identity(self, role: str, display: str | None, addr: str | None) -> list[Finding]:
        domain = domain_of_address(addr)
        if not domain:
            return []
        findings: list[Finding] = []
        org = registrable_domain(domain) or domain
        label = domain_label(domain) or ""

        if display and (shown := _EMAIL_IN_TEXT.search(display)):
            shown_addr = shown.group(0).lower()
            if not same_org(domain_of_address(shown_addr), domain):
                findings.append(
                    Finding(
                        signal="headers.display_name_spoof",
                        points=20,
                        severity=Severity.HIGH,
                        message=f"The {role}'s display name shows {shown_addr}, but the "
                        f"mail really comes from {addr}.",
                        evidence={"display": display, "address": addr},
                    )
                )

        impersonated = next(
            (
                brand
                for brand, official in self.brands.items()
                if display and _brand_in(display, brand) and not _is_official(domain, official)
            ),
            None,
        )
        if impersonated:
            findings.append(
                Finding(
                    signal="headers.brand_impersonation",
                    points=25,
                    severity=Severity.HIGH,
                    message=f"The {role} calls itself '{display}' but sends from {org}, "
                    f"which is not a domain {impersonated.title()} uses.",
                    evidence={"brand": impersonated, "display": display, "domain": domain},
                )
            )

        lookalike = self._lookalike(domain, label)
        if lookalike and lookalike != impersonated:
            findings.append(
                Finding(
                    signal="headers.lookalike_domain",
                    points=25,
                    severity=Severity.HIGH,
                    message=f"The {role}'s domain {org} imitates {lookalike.title()}.",
                    evidence={"brand": lookalike, "domain": domain},
                )
            )
        if domain.startswith("xn--") or ".xn--" in domain:
            findings.append(
                Finding(
                    signal="headers.punycode_domain",
                    points=15,
                    severity=Severity.MEDIUM,
                    message=f"The {role}'s domain {domain} uses punycode, which can hide "
                    "lookalike characters.",
                )
            )
        # Machine-generated names in the domain or its subdomains (not the ESP's own hosts).
        random_parts = [p for p in domain.split(".") if looks_random(p)]
        if random_parts:
            findings.append(
                Finding(
                    signal="headers.random_domain",
                    points=10,
                    severity=Severity.MEDIUM,
                    message=f"The {role}'s domain {domain} looks machine-generated.",
                    evidence={"parts": random_parts},
                )
            )
        tld = domain.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            findings.append(
                Finding(
                    signal="headers.suspicious_tld",
                    points=5,
                    severity=Severity.LOW,
                    message=f"The {role}'s domain uses .{tld}, a TLD heavily abused for phishing.",
                )
            )
        return findings

    def _lookalike(self, domain: str, label: str) -> str | None:
        """Brand whose official domain this one imitates (typo or brand + bait words)."""
        if len(label) < 5 or any(_is_official(domain, o) for o in self.brands.values()):
            return None
        for brand, official in self.brands.items():
            for real in official:
                real_label = domain_label(real) or ""
                if len(real_label) < 5 or label == real_label:
                    continue
                if levenshtein(label, real_label) <= (1 if len(real_label) < 8 else 2):
                    return brand  # paypa1, rnicrosoft, amazom
                if _embeds_brand(label, real_label):
                    return brand  # paypal-secure, microsoftsupport
        return None


# Words phishers glue onto a brand name; used so `paypalsecure` matches but `pineapple` doesn't.
_BAIT_WORDS = {
    "secure", "security", "login", "signin", "support", "account", "accounts", "verify",
    "verification", "update", "service", "services", "help", "helpdesk", "billing", "online",
    "auth", "wallet", "team", "alert", "alerts", "notice", "mail", "info", "customer", "id",
    "center", "centre", "app", "web", "official", "access", "confirm", "pay", "payment",
}  # fmt: skip


def _embeds_brand(label: str, brand: str) -> bool:
    if brand not in label:
        return False
    if re.search(rf"(?:^|-){re.escape(brand)}(?:-|$)", label):
        return True
    rest = [w for w in re.split(r"[^a-z0-9]+", label.replace(brand, " ")) if w]
    return bool(rest) and all(w in _BAIT_WORDS or w.isdigit() for w in rest)
