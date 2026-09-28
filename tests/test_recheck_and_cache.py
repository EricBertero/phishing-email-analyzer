import asyncio
import sqlite3
from contextlib import closing
from datetime import timedelta

from conftest import build_eml
from fake_gmail import FakeGmail
from sqlmodel import Session, select

from phishanalyzer.analyzers import offline_analyzers
from phishanalyzer.models import Finding, Severity
from phishanalyzer.providers.gmail import GmailProvider
from phishanalyzer.scanner import Scanner
from phishanalyzer.storage import ScannedEmail, Store
from phishanalyzer.storage.db import utcnow


def test_intel_cache_persists_and_expires(tmp_path):
    db = tmp_path / "x.db"
    cache = Store(db).intel_cache()
    cache.set("vt:file:abc", {"v": {"malicious": 3}}, ttl_seconds=3600)
    cache.set("vt:file:none", {"v": None}, ttl_seconds=3600)
    reopened = Store(db).intel_cache()
    assert reopened.get("vt:file:abc") == {"v": {"malicious": 3}}
    assert reopened.get("vt:file:none") == {"v": None}
    cache.set("vt:file:old", {"v": 1}, ttl_seconds=-1)
    assert reopened.get("vt:file:old") is None
    assert reopened.get("missing") is None


def test_old_database_gains_new_columns(tmp_path):
    """A DB created by Phase 3 (no `rechecks` column) keeps working after upgrade."""
    db = tmp_path / "old.db"
    with closing(sqlite3.connect(db)) as conn, conn:
        conn.execute(
            "CREATE TABLE scanned_emails (id INTEGER PRIMARY KEY, provider VARCHAR NOT NULL,"
            " provider_id VARCHAR NOT NULL, message_id VARCHAR, subject VARCHAR NOT NULL,"
            " from_addr VARCHAR, from_display VARCHAR, sender_ip VARCHAR, sent_at DATETIME,"
            " scanned_at DATETIME NOT NULL, score INTEGER, level VARCHAR(10),"
            " partial BOOLEAN NOT NULL, findings JSON, labeled BOOLEAN NOT NULL,"
            " error VARCHAR, UNIQUE (provider, provider_id))"
        )
        conn.execute(
            "INSERT INTO scanned_emails (provider, provider_id, subject, scanned_at, partial,"
            " labeled) VALUES ('gmail', 'm1', 's', '2026-09-01 00:00:00.000000', 0, 1)"
        )
    store = Store(db)
    [row] = store.recent()
    assert row.provider_id == "m1" and row.rechecks == 0


class FlakyIntel:
    """Analyzer whose lookup is unavailable on the first call and works afterwards."""

    name = "flaky"

    def __init__(self):
        self.calls = 0

    async def analyze(self, email):
        self.calls += 1
        if self.calls == 1:
            return [
                Finding(
                    signal="flaky.unavailable",
                    points=0,
                    severity=Severity.INFO,
                    message="down",
                    unavailable=True,
                )
            ]
        return [
            Finding(
                signal="urls.vt_malicious",
                points=50,
                severity=Severity.CRITICAL,
                message="bad link",
                force_critical=True,
            )
        ]


def age_rows(store: Store, minutes: int) -> None:
    with Session(store.engine) as s:
        for row in s.exec(select(ScannedEmail)).all():
            row.scanned_at = utcnow() - timedelta(minutes=minutes)
            s.add(row)
        s.commit()


def test_partial_verdict_is_rechecked_and_relabelled(settings):
    gmail, store, flaky = FakeGmail(), Store(":memory:"), FlakyIntel()
    scanner = Scanner(settings, GmailProvider(gmail), store, [*offline_analyzers(), flaky])
    gmail.deliver("m1", build_eml(subject="hello"))

    asyncio.run(scanner.poll_once())
    [row] = store.recent()
    assert row.partial and row.level.value == "clean"
    assert "Phish/Clean" in gmail.label_names_of("m1")

    # Too recent to re-check yet.
    assert asyncio.run(scanner.poll_once()).rechecked == 0

    age_rows(store, minutes=15)
    result = asyncio.run(scanner.poll_once())
    assert result.rechecked == 1
    [row] = store.recent()
    assert not row.partial and row.level.value == "critical" and row.rechecks == 1
    assert gmail.label_names_of("m1") >= {"Phish/Critical"}
    assert "Phish/Clean" not in gmail.label_names_of("m1")


def test_rechecks_are_bounded(settings):
    class AlwaysDown(FlakyIntel):
        async def analyze(self, email):
            return [
                Finding(
                    signal="x.unavailable",
                    points=0,
                    severity=Severity.INFO,
                    message="down",
                    unavailable=True,
                )
            ]

    gmail, store = FakeGmail(), Store(":memory:")
    scanner = Scanner(settings, GmailProvider(gmail), store, [AlwaysDown()])
    gmail.deliver("m1", build_eml())
    asyncio.run(scanner.poll_once())
    for _ in range(5):
        age_rows(store, minutes=15)
        asyncio.run(scanner.poll_once())
    assert store.recent()[0].rechecks == 3


def test_deleted_message_stops_rechecks(settings):
    gmail, store = FakeGmail(), Store(":memory:")
    scanner = Scanner(settings, GmailProvider(gmail), store, [FlakyIntel()])
    gmail.deliver("m1", build_eml())
    asyncio.run(scanner.poll_once())
    del gmail.messages_by_id["m1"]
    age_rows(store, minutes=15)
    assert asyncio.run(scanner.poll_once()).rechecked == 0
    assert store.due_for_recheck("gmail", min_age=timedelta(0)) == []
