"""Combine findings into a 0-100 score and a level."""

from __future__ import annotations

from phishanalyzer.config import Settings
from phishanalyzer.models import Finding, Level, Verdict

MAX_SCORE = 100


def score_findings(findings: list[Finding], settings: Settings) -> Verdict:
    # Apply per-signal weight overrides from config.yaml.
    weighted = [
        f.model_copy(update={"points": settings.weights[f.signal]})
        if f.signal in settings.weights
        else f
        for f in findings
    ]
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
