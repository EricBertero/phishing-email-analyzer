import asyncio
from datetime import UTC, datetime

import pytest
from conftest import build_eml, make_email
from fake_gmail import FakeGmail

from phishanalyzer.models import Finding, Level, Severity, Verdict
from phishanalyzer.providers.gmail import GmailProvider
from phishanalyzer.scanner import Scanner
from phishanalyzer.storage import Store

PHISH = build_eml(
    from_="PayPal Security <alert@paypal-secure-login.com>",
    subject="Urgent: your account has been suspended",
    html='<a href="http://185.12.4.9/login">https://www.paypal.com/signin</a>',
    headers=[("Reply-To", "x@mail-help.example")],
)
BENIGN = build_eml(subject="September newsletter", text="New articles this month.")


@pytest.fixture
def gmail():
    return FakeGmail()


@pytest.fixture
def store():
    return Store(":memory:")


@pytest.fixture
def scanner(settings, gmail, store):
    settings.backfill_count = 10
    return Scanner(settings, GmailProvider(gmail), store)


def poll(scanner):
    return asyncio.run(scanner.poll_once())


def test_first_run_backfills_then_only_new_mail(scanner, gmail, store):
    gmail.deliver("old1", BENIGN)
    gmail.deliver("old2", PHISH)
    first = poll(scanner)
    assert first.scanned == 2 and first.cursor_advanced
    assert "Phish/Clean" in gmail.label_names_of("old1")
    assert gmail.label_names_of("old2") & {"Phish/High", "Phish/Critical"}

    gmail.deliver("new1", PHISH)
    second = poll(scanner)
    assert second.scanned == 1
    assert poll(scanner).scanned == 0  # nothing new
    assert {r.provider_id for r in store.recent()} == {"old1", "old2", "new1"}


def test_restart_does_not_rescan(settings, gmail, store):
    gmail.deliver("m1", BENIGN)
    poll(Scanner(settings, GmailProvider(gmail), store))
    gmail.deliver("m2", BENIGN)
    result = poll(Scanner(settings, GmailProvider(gmail), store))  # "restarted" process
    assert result.scanned == 1


def test_fetch_failure_keeps_cursor_so_mail_is_not_lost(scanner, gmail, store):
    poll(scanner)
    cursor = store.get_cursor("gmail")
    gmail.deliver("m1", PHISH)
    gmail.fail_next["messages.get"] = 503
    failed = poll(scanner)
    assert failed.failed == 1 and not failed.cursor_advanced
    assert store.get_cursor("gmail") == cursor
    retry = poll(scanner)
    assert retry.scanned == 1 and retry.cursor_advanced


def test_expired_cursor_resyncs(scanner, gmail, store):
    poll(scanner)
    gmail.deliver("m1", BENIGN)
    gmail.expired_before = 10**9
    result = poll(scanner)
    assert result.scanned == 1  # found via the recent-messages resync


def test_deleted_message_is_skipped(scanner, gmail):
    poll(scanner)
    gmail.deliver("m1", BENIGN)
    del gmail.messages_by_id["m1"]
    result = poll(scanner)
    assert result.scanned == 0 and result.failed == 0 and result.cursor_advanced


def test_dry_run_never_modifies_gmail(scanner, gmail, store):
    scanner.settings.dry_run = True
    gmail.deliver("m1", PHISH)
    poll(scanner)
    assert "messages.modify" not in gmail.calls
    assert not store.recent()[0].labeled

    # Turning dry-run off labels what was scanned meanwhile.
    scanner.settings.dry_run = False
    poll(scanner)
    assert gmail.label_names_of("m1") & {"Phish/High", "Phish/Critical"}


def test_label_failure_is_retried_next_poll(scanner, gmail, store):
    poll(scanner)
    gmail.deliver("m1", BENIGN)
    gmail.fail_next["messages.modify"] = 500
    poll(scanner)
    assert not store.recent()[0].labeled
    poll(scanner)
    assert store.recent()[0].labeled
    assert "Phish/Clean" in gmail.label_names_of("m1")


def test_quarantine_only_critical(scanner, gmail):
    scanner.settings.quarantine_critical = True
    gmail.deliver("safe", BENIGN)
    poll(scanner)
    assert "INBOX" in gmail.label_names_of("safe")


def test_unparseable_message_is_recorded_not_blocking(scanner, gmail, store, monkeypatch):
    import phishanalyzer.scanner as scanner_module

    def boom(raw, provider_id=None):
        raise ValueError("cannot parse")

    monkeypatch.setattr(scanner_module, "parse_message", boom)
    gmail.deliver("m1", b"garbage")
    result = poll(scanner)
    assert result.cursor_advanced
    [row] = store.recent()
    assert row.error and "cannot parse" in row.error and row.level is None


def test_run_forever_stops(scanner, gmail):
    async def go():
        stop = asyncio.Event()
        task = asyncio.create_task(scanner.run_forever(stop))
        await asyncio.sleep(0.05)
        stop.set()
        await asyncio.wait_for(task, timeout=2)

    gmail.deliver("m1", BENIGN)
    asyncio.run(go())
    assert "messages.modify" in gmail.calls


def test_store_roundtrip_and_upsert(store):
    email = make_email()
    email.provider_id = "x1"
    verdict = Verdict(
        score=42,
        level=Level.SUSPICIOUS,
        findings=[Finding(signal="a.b", points=42, severity=Severity.MEDIUM, message="m")],
    )
    row = store.save_result("gmail", email, verdict)
    assert row.id and row.level == Level.SUSPICIOUS
    assert row.findings[0]["signal"] == "a.b"
    assert row.sent_at == datetime(2025, 9, 1, 17, 0, tzinfo=UTC)
    assert store.is_scanned("gmail", "x1") and not store.is_scanned("gmail", "x2")

    rescored = verdict.model_copy(update={"score": 90, "level": Level.CRITICAL})
    again = store.save_result("gmail", email, rescored)
    assert again.id == row.id and again.level == Level.CRITICAL
    assert len(store.recent()) == 1
    assert store.recent(level=Level.CRITICAL)[0].score == 90
    assert store.recent(level=Level.CLEAN) == []


def test_cursor_persistence(tmp_path):
    db = tmp_path / "sub" / "x.db"
    Store(db).set_cursor("gmail", "123")
    assert Store(db).get_cursor("gmail") == "123"
    assert Store(db).get_cursor("other") is None
