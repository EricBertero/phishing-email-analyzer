"""Combine findings into a 0-100 score and a level."""

from __future__ import annotations

from phishanalyzer.config import Settings
from phishanalyzer.models import Finding, Level, Severity, Verdict

MAX_SCORE = 100

# Signals that are each only suspicious, but together mean the email is Critical.
COMBINATIONS: list[tuple[frozenset[str], str, str]] = [
    (
        frozenset({"reputation.sender_domain_blocklisted", "auth.dmarc_fail"}),
        "combo.blocklisted_spoof",
        "The sender's domain is on the Spamhaus DBL and failed DMARC.",
    ),
]


def _combinations(findings: list[Finding]) -> list[Finding]:
    present = {f.signal for f in findings if f.points > 0 and not f.unavailable}
    return [
        Finding(
            signal=signal,
            points=0,
            severity=Severity.CRITICAL,
            message=message,
            evidence={"signals": sorted(required)},
            force_critical=True,
        )
        for required, signal, message in COMBINATIONS
        if required <= present
    ]


def score_findings(findings: list[Finding], settings: Settings) -> Verdict:
    # Apply per-signal weight overrides from config.yaml.
    weighted = [
        f.model_copy(update={"points": settings.weights[f.signal]})
        if f.signal in settings.weights
        else f
        for f in findings
    ]
    weighted += _combinations(weighted)
    total = sum(max(f.points, 0) for f in weighted if not f.unavailable)
    score = min(total, MAX_SCORE)
    level = settings.thresholds.level_for(score)

    if any(f.force_critical for f in weighted):
        level = Level.CRITICAL
        score = max(score, settings.thresholds.critical)

    ordered = sorted(weighted, key=lambda f: (f.force_critical, f.points), reverse=True)
    return Verdict(
        score=score,
        level=level,
        findings=ordered,
        partial=any(f.unavailable for f in weighted),
    )
