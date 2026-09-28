import asyncio
import re
from datetime import UTC, date, datetime, timedelta

import pytest
from conftest import FIXTURES, build_eml
from fake_gmail import FakeGmail
from fastapi.testclient import TestClient
from sqlmodel import Session

from phishanalyzer.analyzers import offline_analyzers
from phishanalyzer.models import Level
from phishanalyzer.providers.gmail import GmailProvider
from phishanalyzer.reporting.reporter import Reporter
from phishanalyzer.scanner import Scanner
from phishanalyzer.storage import JobStatus, ScannedEmail, Store
from phishanalyzer.web.app import Services, create_app
from phishanalyzer.web.security import host_of, is_loopback
from phishanalyzer.web.stats import BAR_MAX, GAP, build_chart, nice_max

PHISH = build_eml(
    from_="PayPal Security <alert@paypal-secure-login.com>",
    subject="Urgent: your account has been suspended",
    html='<a href="http://185.12.4.9/login">https://www.paypal.com/signin</a>'
    '<form action="https://x.example/p"></form>',
    headers=[("Reply-To", "x@mail-help.example")],
)


@pytest.fixture
def env(settings, tmp_path):
    settings.paths.reports = tmp_path / "reports"
    settings.reports.pdf = False
    gmail, store = FakeGmail(), Store(":memory:")
    reporter = Reporter(settings, store, None)
    scanner = Scanner(settings, GmailProvider(gmail), store, None, reporter)
    services = Services(settings, store, offline_analyzers(), reporter, scanner)
    client = TestClient(create_app(services), base_url="http://127.0.0.1:8000")
    return type(
        "Env",
        (),
        {
            "gmail": gmail,
            "store": store,
            "services": services,
            "client": client,
            "scanner": scanner,
            "settings": settings,
        },
    )


def csrf_of(env) -> str:
    return env.services.csrf_token


def deliver_and_scan(env, message_id="m1", raw=PHISH):
    env.gmail.deliver(message_id, raw)
    asyncio.run(env.scanner.poll_once())
    return env.store.get_row("gmail", message_id)


# --- pages ------------------------------------------------------------------------


def test_empty_dashboard_pages_render(env):
    for path in ("/", "/emails", "/sandbox", "/sandbox?show=all", "/upload"):
        response = env.client.get(path)
        assert response.status_code == 200, path
    assert "Nothing scanned yet" in env.client.get("/emails").text


def test_overview_counts_and_chart(env):
    deliver_and_scan(env, "bad", PHISH)
    deliver_and_scan(env, "ok", build_eml(subject="Newsletter"))
    html = env.client.get("/").text
    assert re.search(r'Critical</span></div><div class="value">1<', html)
    assert html.count('class="col"') == 14
    assert "paypal-secure-login.com" in html  # top risky sender
    assert "Show as table" in html


def test_email_list_filters_search_and_detail(env):
    bad = deliver_and_scan(env, "bad", PHISH)
    deliver_and_scan(env, "ok", build_eml(subject="Team newsletter"))
    assert "Team newsletter" in env.client.get("/emails").text
    critical = env.client.get("/emails?level=critical").text
    assert "Urgent" in critical and "Team newsletter" not in critical
    assert "Team newsletter" in env.client.get("/emails?q=newsletter").text
    assert "Urgent" not in env.client.get("/emails?q=newsletter").text
    assert env.client.get("/emails?level=bogus").status_code == 200  # ignored, not an error

    detail = env.client.get(f"/emails/{bad.id}").text
    assert "headers.brand_impersonation" in detail and "Open report" in detail
    assert env.client.get("/emails/9999").status_code == 404


def test_pagination(env):
    for n in range(55):
        env.store.save_result("gmail", _email(f"id{n}", f"Subject {n}"), _verdict(Level.CLEAN))
    first = env.client.get("/emails").text
    assert "Page 1 of 2" in first and "Older" in first
    second = env.client.get("/emails?p=2").text
    assert "Page 2 of 2" in second and "Newer" in second


def test_attacker_content_is_escaped(env):
    row = deliver_and_scan(
        env, "xss", build_eml(subject="<script>alert(1)</script>", from_='"<img src=x>" <a@b.com>')
    )
    for page in ("/emails", f"/emails/{row.id}"):
        html = env.client.get(page).text
        assert "<script>alert(1)" not in html and "<img src=x>" not in html
        assert "&lt;script&gt;" in html


# --- actions ------------------------------------------------------------------------


def test_rescan_and_report_actions(env):
    row = deliver_and_scan(env, "m1", build_eml(subject="Newsletter"))
    response = env.client.post(
        f"/emails/{row.id}/rescan", data={"csrf": csrf_of(env)}, follow_redirects=False
    )
    assert response.status_code == 303 and response.headers["location"].endswith("notice=rescanned")
    response = env.client.post(
        f"/emails/{row.id}/report", data={"csrf": csrf_of(env)}, follow_redirects=False
    )
    assert response.headers["location"].endswith("notice=reported")
    assert env.store.get_report("gmail", "m1") is not None  # report even for a clean email


def test_actions_need_csrf_token(env):
    row = deliver_and_scan(env)
    for path in (f"/emails/{row.id}/rescan", f"/emails/{row.id}/report"):
        response = env.client.post(path, data={"csrf": "wrong"}, follow_redirects=False)
        assert response.headers["location"].endswith("notice=bad-csrf")


def test_rescan_of_deleted_message(env):
    row = deliver_and_scan(env)
    del env.gmail.messages_by_id["m1"]
    response = env.client.post(
        f"/emails/{row.id}/rescan", data={"csrf": csrf_of(env)}, follow_redirects=False
    )
    assert response.headers["location"].endswith("notice=gone")


def test_sandbox_decisions(env):
    for n in (1, 2):
        env.store.enqueue_job(
            "gmail", f"m{n}", f"sha{n}", f"f{n}.pdf", 10, JobStatus.AWAITING_APPROVAL
        )
    page = env.client.get("/sandbox").text
    assert "f1.pdf" in page and "Upload all awaiting" in page
    post = env.client.post(
        "/sandbox/decide",
        data={"csrf": csrf_of(env), "action": "approve", "job_id": "1"},
        follow_redirects=False,
    )
    assert post.headers["location"] == "/sandbox?notice=approved"
    assert env.store.get_job(1).status is JobStatus.PENDING
    post = env.client.post(
        "/sandbox/decide", data={"csrf": csrf_of(env), "action": "reject"}, follow_redirects=False
    )
    assert post.headers["location"] == "/sandbox?notice=rejected"
    assert env.store.get_job(2).status is JobStatus.REJECTED
    again = env.client.post(
        "/sandbox/decide", data={"csrf": csrf_of(env), "action": "reject"}, follow_redirects=False
    )
    assert again.headers["location"] == "/sandbox?notice=none"


def test_sandbox_redirect_is_local_only(env):
    post = env.client.post(
        "/sandbox/decide",
        data={"csrf": csrf_of(env), "action": "reject", "next": "//evil.com/x"},
        follow_redirects=False,
    )
    assert post.headers["location"].startswith("/?")


def test_notices_are_never_reflected(env):
    html = env.client.get("/?notice=<b>pwned</b>").text
    assert "pwned" not in html


# --- upload ---------------------------------------------------------------------------


def test_upload_eml(env):
    raw = (FIXTURES / "test1.eml").read_bytes()
    response = env.client.post(
        "/upload",
        data={"csrf": csrf_of(env), "report": "true"},
        files={"file": ("test1.eml", raw, "message/rfc822")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    row_id = int(response.headers["location"].rsplit("/", 1)[1])
    row = env.store.get_row_by_id(row_id)
    assert row.provider == "upload" and row.level is Level.CRITICAL
    assert env.store.get_report("upload", row.provider_id) is not None
    detail = env.client.get(f"/emails/{row_id}").text
    assert "uploaded" in detail.lower() and "Analyse again" not in detail


@pytest.mark.parametrize(
    ("content", "status", "message"),
    [(b"", 400, "empty"), (b"%PDF-1.7 not an email", 400, "look like an email")],
)
def test_upload_rejects_bad_files(env, content, status, message):
    response = env.client.post(
        "/upload", data={"csrf": csrf_of(env)}, files={"file": ("x.eml", content, "message/rfc822")}
    )
    assert response.status_code == status and message in response.text


def test_upload_needs_csrf(env):
    response = env.client.post(
        "/upload", data={"csrf": "nope"}, files={"file": ("x.eml", PHISH, "message/rfc822")}
    )
    assert response.status_code == 403
    assert env.store.recent() == []


# --- security ---------------------------------------------------------------------------


def test_foreign_host_header_is_refused(env):
    response = env.client.get("/", headers={"host": "evil.com"})
    assert response.status_code == 400


@pytest.mark.parametrize("origin", ["https://evil.com", "null", "http://evil.localhost.com"])
def test_cross_origin_posts_are_refused(env, origin):
    response = env.client.post(
        "/sandbox/decide",
        headers={"origin": origin},
        data={"csrf": csrf_of(env), "action": "reject"},
    )
    assert response.status_code == 403


def test_same_origin_post_allowed(env):
    response = env.client.post(
        "/sandbox/decide",
        headers={"origin": "http://127.0.0.1:8000"},
        data={"csrf": csrf_of(env), "action": "reject"},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_security_headers(env):
    headers = env.client.get("/").headers
    assert "script-src 'self'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "same-origin"
    assert headers["x-frame-options"] == "DENY"


def test_reports_are_served_with_script_free_csp(env):
    deliver_and_scan(env, "bad", PHISH)
    report = env.store.get_report("gmail", "bad")
    response = env.client.get(f"/reports/{report.id}")
    assert response.status_code == 200 and "CRITICAL" in response.text
    assert response.headers["content-security-policy"].startswith("default-src 'none'")
    assert env.client.get(f"/reports/{report.id}/pdf").status_code == 404  # pdf disabled here
    assert env.client.get("/reports/999").status_code == 404


def test_report_paths_outside_reports_dir_are_refused(env, tmp_path):
    deliver_and_scan(env, "bad", PHISH)
    report = env.store.get_report("gmail", "bad")
    secret = tmp_path / "secret.txt"
    secret.write_text("token")
    with Session(env.store.engine) as s:
        tampered = s.get(type(report), report.id)
        tampered.html_path = str(secret)
        s.add(tampered)
        s.commit()
    assert env.client.get(f"/reports/{report.id}").status_code == 404


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("127.0.0.1:8000", True),
        ("localhost", True),
        ("[::1]:8000", True),
        ("127.5.5.5", True),
        ("0.0.0.0", False),
        ("192.168.1.10:8000", False),
        ("evil.com", False),
        ("localhost.evil.com", False),
        ("", False),
    ],
)
def test_loopback_detection(value, expected):
    assert is_loopback(host_of(value)) is expected


def test_dashboard_without_mailbox_disables_actions(settings):
    store = Store(":memory:")
    store.save_result("gmail", _email("m1", "Hello"), _verdict(Level.CLEAN))
    client = TestClient(
        create_app(Services(settings, store, offline_analyzers())), base_url="http://127.0.0.1"
    )
    detail = client.get("/emails/1").text
    assert "Analyse again" not in detail and "Not watching a mailbox" in detail
    post = client.post("/emails/1/rescan", data={"csrf": "x"}, follow_redirects=False)
    assert "bad-csrf" in post.headers["location"]


# --- chart geometry ---------------------------------------------------------------------


def _email(provider_id, subject):
    from conftest import make_email

    email = make_email(subject=subject)
    email.provider_id = provider_id
    return email


def _verdict(level):
    from phishanalyzer.models import Verdict

    return Verdict(
        score={Level.CLEAN: 0, Level.CRITICAL: 90}.get(level, 50), level=level, findings=[]
    )


def _rows(counts: dict[Level, int], day: date):
    when = datetime(day.year, day.month, day.day, 12, tzinfo=UTC)
    return [
        ScannedEmail(provider="t", provider_id=f"{lv}{i}", scanned_at=when, level=lv)
        for lv, n in counts.items()
        for i in range(n)
    ]


@pytest.mark.parametrize(
    ("value", "axis"), [(0, 4), (3, 4), (7, 8), (43, 50), (99, 100), (101, 125)]
)
def test_nice_axis(value, axis):
    top, step = nice_max(value)
    assert top == axis and top >= value and top // step <= 5 and step >= 1


def test_chart_groups_stacking_and_marks():
    today = date(2026, 9, 28)
    rows = _rows({Level.CLEAN: 3, Level.LOW: 2, Level.HIGH: 1, Level.CRITICAL: 4}, today)
    rows += _rows({Level.SUSPICIOUS: 1}, today - timedelta(days=3))
    rows += _rows({Level.CRITICAL: 9}, today - timedelta(days=30))  # outside the window
    chart = build_chart(rows, today)
    assert len(chart.columns) == 14 and chart.total == 11
    last = chart.columns[-1]
    assert last.counts == {"ok": 5, "suspicious": 0, "high": 1, "critical": 4}
    assert last.level_counts["low"] == 2  # Low kept separately for tooltip/table
    assert [s.group for s in last.segments] == ["ok", "high", "critical"]
    assert last.width <= BAR_MAX
    # Only the top segment gets the rounded data-end (the path uses Q curves).
    assert [("Q" in s.path) for s in last.segments] == [False, False, True]
    # Segments are separated by the surface gap.
    tops = [float(re.findall(r"[-\d.]+", s.path)[1]) for s in last.segments]
    bottoms = [
        float(
            re.search(r"V([-\d.]+)Z$|V([-\d.]+)H", s.path).group(1)
            or re.search(r"V([-\d.]+)H", s.path).group(1)
        )
        for s in last.segments
    ]
    assert bottoms[0] == pytest.approx(chart.baseline)
    assert abs((tops[0] - bottoms[1]) - GAP) < 0.01


def test_empty_chart_is_valid():
    chart = build_chart([], date(2026, 9, 28))
    assert chart.total == 0 and all(not c.segments for c in chart.columns)
    assert [v for _, v in chart.ticks] == [0, 1, 2, 3, 4]


def test_demo_seed_covers_every_level(settings, tmp_path):
    from phishanalyzer.web.demo import seed

    settings.paths.reports = tmp_path / "reports"
    settings.reports.pdf = False
    store = Store(":memory:")
    asyncio.run(seed(settings, store, count=60))
    levels = {Level(r.level) for r in store.recent(limit=100)}
    assert levels == set(Level)
    assert store.count_jobs(JobStatus.AWAITING_APPROVAL) >= 1
    assert store.reports()
