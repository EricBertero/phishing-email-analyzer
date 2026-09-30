"""Numbers and chart geometry for the overview page.

The chart is a stacked column per day. Verdict levels are *states* (clean -> critical),
so they wear the dashboard's verdict scale (see dashboard.css): a calm neutral for mail
that needs nothing, and the brand's reds for threats, so teal stays the one accent. The
scale has four steps, so Clean and Low share the neutral step as one group; the stat
tiles and the table view still give every level separately. Geometry follows the house
mark specs: columns <= 24px, a 2px surface gap between stacked segments, a 4px rounded
data-end on each column only.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from phishanalyzer.domains import domain_of_address, registrable_domain
from phishanalyzer.models import Level
from phishanalyzer.storage import JobStatus, ScannedEmail, Store

DAYS = 14

# Stack order bottom -> top; the most severe group sits on top, where the eye lands.
GROUPS: list[tuple[str, str, tuple[Level, ...]]] = [
    ("ok", "Clean / low", (Level.CLEAN, Level.LOW)),
    ("suspicious", "Suspicious", (Level.SUSPICIOUS,)),
    ("high", "High", (Level.HIGH,)),
    ("critical", "Critical", (Level.CRITICAL,)),
]

# Plot geometry (SVG user units == CSS px at 100% width).
WIDTH, HEIGHT = 720, 240
PAD_LEFT, PAD_RIGHT, PAD_TOP, PAD_BOTTOM = 40, 8, 12, 28
BAR_MAX = 24
GAP = 2
RADIUS = 4


@dataclass
class Segment:
    group: str
    count: int
    path: str


@dataclass
class Column:
    day: date
    label: str  # axis label, e.g. "3 Sep"
    total: int
    counts: dict[str, int]  # per group
    level_counts: dict[str, int]  # per level, for the tooltip/table
    x: float
    width: float
    hit_x: float
    hit_width: float
    segments: list[Segment] = field(default_factory=list)


@dataclass
class Chart:
    width: int
    height: int
    columns: list[Column]
    ticks: list[tuple[float, int]]  # (y, value)
    baseline: float
    plot_left: float
    plot_right: float
    groups: list[tuple[str, str]]
    total: int


def nice_max(value: int) -> tuple[int, int]:
    """A clean integer axis maximum and step, at most 5 intervals: 7 -> (8, 2), 43 -> (50, 10)."""
    if value <= 4:
        return 4, 1
    raw_step = value / 5
    magnitude = 10 ** math.floor(math.log10(raw_step))
    # 2.5 only when it stays a whole number (25, 250, ...).
    multiples = (1, 2, 5, 10) if magnitude < 10 else (1, 2, 2.5, 5, 10)
    step = next(int(m * magnitude) for m in multiples if m * magnitude >= raw_step)
    return math.ceil(value / step) * step, step


def rounded_top_rect(x: float, y: float, w: float, h: float, r: float) -> str:
    """SVG path: rectangle with rounded top corners, square at the baseline."""
    r = min(r, w / 2, h)
    return (
        f"M{x:.2f},{y + h:.2f}V{y + r:.2f}"
        f"Q{x:.2f},{y:.2f} {x + r:.2f},{y:.2f}"
        f"H{x + w - r:.2f}Q{x + w:.2f},{y:.2f} {x + w:.2f},{y + r:.2f}"
        f"V{y + h:.2f}Z"
    )


def plain_rect(x: float, y: float, w: float, h: float) -> str:
    return f"M{x:.2f},{y:.2f}H{x + w:.2f}V{y + h:.2f}H{x:.2f}Z"


def build_chart(rows: list[ScannedEmail], today: date | None = None) -> Chart:
    today = today or datetime.now(UTC).date()
    days = [today - timedelta(days=offset) for offset in range(DAYS - 1, -1, -1)]
    per_day: dict[date, Counter[str]] = {d: Counter() for d in days}
    for row in rows:
        if row.level is None:
            continue
        day = (
            row.scanned_at.astimezone(UTC).date()
            if row.scanned_at.tzinfo
            else row.scanned_at.date()
        )
        if day in per_day:
            per_day[day][Level(row.level).value] += 1

    totals = [sum(c.values()) for c in per_day.values()]
    axis_max, step = nice_max(max(totals, default=0))
    plot_left, plot_right = PAD_LEFT, WIDTH - PAD_RIGHT
    baseline = HEIGHT - PAD_BOTTOM
    plot_height = baseline - PAD_TOP
    band = (plot_right - plot_left) / len(days)
    bar = min(BAR_MAX, band * 0.6)

    columns = []
    for index, day in enumerate(days):
        level_counts = per_day[day]
        counts = {key: sum(level_counts[lv.value] for lv in levels) for key, _, levels in GROUPS}
        total = sum(counts.values())
        x = plot_left + index * band + (band - bar) / 2
        column = Column(
            day=day,
            label=f"{day.day} {day.strftime('%b')}",
            total=total,
            counts=counts,
            level_counts={lv.value: level_counts[lv.value] for lv in Level},
            x=x,
            width=bar,
            hit_x=plot_left + index * band,
            hit_width=band,
        )
        # Stack from the baseline up; each segment's height is proportional to its
        # count, and the 2px gap is taken out of the segment above it.
        present = [(key, counts[key]) for key, _, _ in GROUPS if counts[key] > 0]
        y = baseline
        for position, (key, count) in enumerate(present):
            top = y - count / axis_max * plot_height
            # The surface gap separates a segment from the one below it.
            bottom = y - (GAP if position > 0 else 0)
            if bottom - top > 0.5:  # thinner than the gap: tooltip and table only
                is_top = position == len(present) - 1
                path = (
                    rounded_top_rect(x, top, bar, bottom - top, RADIUS)
                    if is_top
                    else plain_rect(x, top, bar, bottom - top)
                )
                column.segments.append(Segment(key, count, path))
            y = top
        columns.append(column)

    ticks = [
        (baseline - value / axis_max * plot_height, value) for value in range(0, axis_max + 1, step)
    ]
    return Chart(
        width=WIDTH,
        height=HEIGHT,
        columns=columns,
        ticks=ticks,
        baseline=baseline,
        plot_left=plot_left,
        plot_right=plot_right,
        groups=[(key, label) for key, label, _ in GROUPS],
        total=sum(totals),
    )


@dataclass
class Overview:
    chart: Chart
    level_totals: dict[str, int]
    scanned: int
    partial: int
    awaiting_approval: int
    high_risk: list[ScannedEmail]
    top_domains: list[tuple[str, int]]
    top_findings: list[tuple[str, int]]


def build_overview(store: Store, now: datetime | None = None) -> Overview:
    now = now or datetime.now(UTC)
    since = datetime.combine(now.date() - timedelta(days=DAYS - 1), datetime.min.time(), UTC)
    rows = store.rows_since(since)
    scored = [r for r in rows if r.level is not None]
    levels = Counter(Level(r.level).value for r in scored)
    risky = [r for r in scored if Level(r.level).rank >= Level.HIGH.rank]
    domains = Counter(
        org for r in risky if (org := registrable_domain(domain_of_address(r.from_addr)))
    )
    findings: Counter[str] = Counter()
    for r in scored:
        if Level(r.level).rank >= Level.SUSPICIOUS.rank:
            for f in r.findings:
                if f.get("points", 0) > 0 or f.get("force_critical"):
                    findings[f["signal"]] += 1
    return Overview(
        chart=build_chart(rows, now.date()),
        level_totals={lv.value: levels[lv.value] for lv in Level},
        scanned=len(scored),
        partial=sum(1 for r in scored if r.partial),
        awaiting_approval=store.count_jobs(JobStatus.AWAITING_APPROVAL),
        high_risk=sorted(risky, key=lambda r: r.scanned_at, reverse=True)[:8],
        top_domains=domains.most_common(6),
        top_findings=findings.most_common(6),
    )
