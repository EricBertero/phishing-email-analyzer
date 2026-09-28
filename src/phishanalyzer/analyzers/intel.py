"""Threat-intel checks: reputation of links, sending IP, domains and attachments.

Only indicators (URLs, hostnames, IPs, file hashes) leave the machine, never message
content. Unreachable services produce `unavailable` findings (partial verdict, re-checked
later), never a failed scan.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import Any

from phishanalyzer.config import Settings
from phishanalyzer.domains import (
    domain_of_address,
    hostname_of_url,
    is_ip,
    is_public_ip,
    registrable_domain,
)
from phishanalyzer.intel.abuseipdb import AbuseIpdbClient
from phishanalyzer.intel.base import IntelUnavailable
from phishanalyzer.intel.spamhaus import SpamhausClient
from phishanalyzer.intel.urlhaus import UrlhausClient
from phishanalyzer.intel.virustotal import VirusTotalClient
from phishanalyzer.models import Email, Finding, Severity

MAX_URLS_PER_EMAIL = 20
MAX_ATTACHMENTS_PER_EMAIL = 5


def unavailable(service: str, errors: list[IntelUnavailable]) -> Finding:
    return Finding(
        signal=f"{service}.unavailable",
        points=0,
        severity=Severity.INFO,
        message=f"{service} lookups could not be completed: {errors[0]}",
        evidence={"errors": sorted({str(e) for e in errors})[:5]},
        unavailable=True,
    )


async def gather_lookups(
    calls: list[tuple[Any, Awaitable[Any]]],
) -> tuple[list[tuple[Any, Any]], list[IntelUnavailable]]:
    """Run lookups concurrently: ([(item, result)], [errors]). Bugs still propagate."""
    results = await asyncio.gather(*(call for _, call in calls), return_exceptions=True)
    ok, errors = [], []
    for (item, _), result in zip(calls, results, strict=True):
        if isinstance(result, IntelUnavailable):
            errors.append(result)
        elif isinstance(result, BaseException):
            raise result
        else:
            ok.append((item, result))
    return ok, errors


def link_urls(email: Email) -> list[str]:
    urls = [u.url for u in email.urls if u.source != "form" and hostname_of_url(u.url)]
    return list(dict.fromkeys(urls))[:MAX_URLS_PER_EMAIL]


def link_hosts(email: Email, limit: int) -> list[str]:
    hosts = (hostname_of_url(url) for url in link_urls(email))
    return list(dict.fromkeys(h for h in hosts if h))[:limit]


def sender_orgs(email: Email) -> set[str]:
    addresses = [email.from_addr, email.forwarded.from_addr if email.forwarded else None]
    return {org for a in addresses if (org := registrable_domain(domain_of_address(a)))}


class UrlhausAnalyzer:
    name = "urlhaus"

    def __init__(self, client: UrlhausClient, settings: Settings):
        self.client = client
        self.max_hosts = settings.intel.max_hosts_per_email

    async def analyze(self, email: Email) -> list[Finding]:
        urls = link_urls(email)
        hosts = link_hosts(email, self.max_hosts)
        url_hits, url_errors = await gather_lookups([(u, self.client.url(u)) for u in urls])
        host_hits, host_errors = await gather_lookups([(h, self.client.host(h)) for h in hosts])
        findings: list[Finding] = []

        listed = [(url, hit) for url, hit in url_hits if hit]
        online = [{"url": u, **h} for u, h in listed if h["status"] == "online"]
        known = [{"url": u, **h} for u, h in listed if h["status"] != "online"]
        if online:
            findings.append(
                Finding(
                    signal="urls.urlhaus_online",
                    points=50,
                    severity=Severity.CRITICAL,
                    force_critical=True,
                    message=f"A link is a live malware-distribution URL on URLhaus "
                    f"({online[0]['threat'] or 'malware'}).",
                    evidence={"urls": online[:5]},
                )
            )
        elif known:
            findings.append(
                Finding(
                    signal="urls.urlhaus_known",
                    points=25,
                    severity=Severity.HIGH,
                    message="A link was previously reported to URLhaus as distributing malware.",
                    evidence={"urls": known[:5]},
                )
            )

        hosts_listed = [{"host": h, **hit} for h, hit in host_hits if hit]
        hosts_online = [h for h in hosts_listed if h["online"]]
        if hosts_online:
            findings.append(
                Finding(
                    signal="urls.urlhaus_host_online",
                    points=30,
                    severity=Severity.HIGH,
                    message=f"Links point to {hosts_online[0]['host']}, which currently "
                    "serves malware according to URLhaus.",
                    evidence={"hosts": hosts_online[:5]},
                )
            )
        elif hosts_listed:
            findings.append(
                Finding(
                    signal="urls.urlhaus_host_known",
                    points=10,
                    severity=Severity.MEDIUM,
                    message=f"Links point to {hosts_listed[0]['host']}, which has served "
                    "malware in the past (URLhaus).",
                    evidence={"hosts": hosts_listed[:5]},
                )
            )

        if errors := url_errors + host_errors:
            findings.append(unavailable(self.name, errors))
        return findings


class SpamhausAnalyzer:
    name = "spamhaus"

    def __init__(self, client: SpamhausClient, settings: Settings):
        self.client = client
        self.max_hosts = settings.intel.max_hosts_per_email

    async def analyze(self, email: Email) -> list[Finding]:
        findings: list[Finding] = []
        errors: list[IntelUnavailable] = []

        if is_public_ip(email.sender_ip):
            hits, errs = await gather_lookups([(email.sender_ip, self.client.ip(email.sender_ip))])
            errors += errs
            for ip, result in hits:
                if not result["codes"]:
                    continue
                policy = result["policy_only"]
                findings.append(
                    Finding(
                        signal="reputation.ip_policy_listed"
                        if policy
                        else "reputation.ip_blocklisted",
                        points=5 if policy else 25,
                        severity=Severity.LOW if policy else Severity.HIGH,
                        message=f"The sending IP {ip} is on Spamhaus ZEN: "
                        f"{', '.join(result['reasons'])}.",
                        evidence={"ip": ip, **result},
                    )
                )

        sender_domains = {
            org
            for addr in (
                email.from_addr,
                email.reply_to,
                email.forwarded.from_addr if email.forwarded else None,
            )
            if (org := registrable_domain(domain_of_address(addr)))
        }
        link_domains = {
            org
            for host in link_hosts(email, self.max_hosts)
            if not is_ip(host) and (org := registrable_domain(host))
        } - sender_domains

        hits, errs = await gather_lookups(
            [(d, self.client.domain(d)) for d in sorted(sender_domains | link_domains)]
        )
        errors += errs
        for domain, result in hits:
            if not result["codes"]:
                continue
            reasons = ", ".join(result["reasons"])
            if domain in sender_domains:
                findings.append(
                    Finding(
                        signal="reputation.sender_domain_blocklisted",
                        points=40 if result["dangerous"] else 25,
                        severity=Severity.HIGH,
                        message=f"The sender's domain {domain} is on the Spamhaus DBL ({reasons}).",
                        evidence={"domain": domain, **result},
                    )
                )
            elif result["abused_legit"]:
                findings.append(
                    Finding(
                        signal="reputation.link_domain_abused",
                        points=15,
                        severity=Severity.MEDIUM,
                        message=f"Links point to {domain}, a legitimate site Spamhaus reports "
                        f"as currently abused ({reasons}).",
                        evidence={"domain": domain, **result},
                    )
                )
            else:
                findings.append(
                    Finding(
                        signal="reputation.link_domain_blocklisted",
                        points=40 if result["dangerous"] else 20,
                        severity=Severity.CRITICAL if result["dangerous"] else Severity.HIGH,
                        force_critical=result["dangerous"],
                        message=f"Links point to {domain}, which is on the Spamhaus DBL "
                        f"({reasons}).",
                        evidence={"domain": domain, **result},
                    )
                )

        if errors:
            findings.append(unavailable(self.name, errors))
        return findings


class AbuseIpdbAnalyzer:
    name = "abuseipdb"

    def __init__(self, client: AbuseIpdbClient):
        self.client = client

    async def analyze(self, email: Email) -> list[Finding]:
        ip = email.sender_ip
        if not is_public_ip(ip):
            return []
        hits, errors = await gather_lookups([(ip, self.client.check(ip))])
        if errors:
            return [unavailable(self.name, errors)]
        result = hits[0][1]
        confidence = result["confidence"]
        if result["whitelisted"] or confidence < 25:
            return []
        high = confidence >= 75
        return [
            Finding(
                signal="reputation.ip_abuse_reports",
                points=25 if high else 10,
                severity=Severity.HIGH if high else Severity.MEDIUM,
                message=f"The sending IP {ip} has an AbuseIPDB abuse confidence of "
                f"{confidence}% ({result['reports']} reports).",
                evidence={"ip": ip, **result},
            )
        ]


class VirusTotalAnalyzer:
    name = "virustotal"

    def __init__(self, client: VirusTotalClient, settings: Settings):
        self.client = client
        self.threshold = settings.vt_malicious_threshold
        self.max_urls = settings.intel.vt_max_urls_per_email

    async def analyze(self, email: Email) -> list[Finding]:
        # Attachments first: the free quota is small and files are the bigger risk.
        attachments = list({a.sha256: a for a in email.attachments if a.size > 0}.values())[
            :MAX_ATTACHMENTS_PER_EMAIL
        ]
        own = sender_orgs(email)
        urls = [u for u in link_urls(email) if registrable_domain(hostname_of_url(u)) not in own][
            : self.max_urls
        ]

        file_hits, file_errors = await gather_lookups(
            [(a, self.client.file(a.sha256)) for a in attachments]
        )
        url_hits, url_errors = await gather_lookups([(u, self.client.url(u)) for u in urls])
        findings: list[Finding] = []

        for att, result in file_hits:
            evidence = {"filename": att.filename, "sha256": att.sha256, "vt": result}
            name = att.filename or att.sha256[:12]
            if result is None:
                findings.append(
                    Finding(
                        signal="attachments.vt_unknown",
                        points=0,
                        severity=Severity.INFO,
                        message=f"VirusTotal has never seen '{name}'.",
                        evidence=evidence,
                    )
                )
            elif result["malicious"] >= self.threshold:
                findings.append(
                    Finding(
                        signal="attachments.vt_malicious",
                        points=60,
                        severity=Severity.CRITICAL,
                        force_critical=True,
                        message=f"'{name}' is flagged malicious by {result['malicious']} "
                        f"VirusTotal engines"
                        + (f" ({result['label']})." if result["label"] else "."),
                        evidence=evidence,
                    )
                )
            elif result["malicious"] or result["suspicious"] >= self.threshold:
                findings.append(
                    Finding(
                        signal="attachments.vt_detections",
                        points=25,
                        severity=Severity.HIGH,
                        message=f"'{name}' is flagged by {result['malicious']} VirusTotal "
                        f"engines as malicious and {result['suspicious']} as suspicious.",
                        evidence=evidence,
                    )
                )
            else:
                findings.append(
                    Finding(
                        signal="attachments.vt_clean",
                        points=0,
                        severity=Severity.INFO,
                        message=f"VirusTotal knows '{name}' and no engine flags it.",
                        evidence=evidence,
                    )
                )

        bad = [(u, r) for u, r in url_hits if r and r["malicious"] >= self.threshold]
        flagged = [(u, r) for u, r in url_hits if r and 0 < r["malicious"] < self.threshold]
        if bad:
            findings.append(
                Finding(
                    signal="urls.vt_malicious",
                    points=50,
                    severity=Severity.CRITICAL,
                    force_critical=True,
                    message=f"A link is flagged malicious by {bad[0][1]['malicious']} "
                    "VirusTotal engines.",
                    evidence={"urls": [{"url": u, **r} for u, r in bad]},
                )
            )
        elif flagged:
            findings.append(
                Finding(
                    signal="urls.vt_detections",
                    points=15,
                    severity=Severity.MEDIUM,
                    message=f"A link is flagged by {flagged[0][1]['malicious']} VirusTotal "
                    "engine(s).",
                    evidence={"urls": [{"url": u, **r} for u, r in flagged]},
                )
            )

        if errors := file_errors + url_errors:
            findings.append(unavailable(self.name, errors))
        return findings
