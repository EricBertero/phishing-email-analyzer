import asyncio
import hashlib
from datetime import timedelta

import pytest
from conftest import build_eml, make_email, run
from fake_gmail import FakeGmail

from phishanalyzer.analyzers import offline_analyzers
from phishanalyzer.analyzers.sandbox import SandboxAnalyzer, verdict_finding, worth_sandboxing
from phishanalyzer.config import SandboxUpload
from phishanalyzer.intel.base import IntelUnavailable
from phishanalyzer.models import Attachment, Level
from phishanalyzer.providers.gmail import GmailProvider
from phishanalyzer.sandbox_worker import SandboxWorker
from phishanalyzer.scanner import Scanner
from phishanalyzer.storage import JobStatus, Store
from phishanalyzer.storage.db import utcnow

PDF = b"%PDF-1.7 quarterly report, unique body 1"
PDF_SHA = hashlib.sha256(PDF).hexdigest()
MALICIOUS = {
    "verdict": "malicious",
    "threat_score": 100,
    "av_detect": 80,
    "family": "Emotet",
    "tags": [],
    "job_id": "j1",
}
CLEAN = {**MALICIOUS, "verdict": "no specific threat", "threat_score": 3, "family": None}


class FakeHA:
    """Stand-in for HybridAnalysisClient."""

    def __init__(self):
        self.reports: dict[str, dict | None] = {}  # sha256 -> overview
        self.overview_error: Exception | None = None
        self.submit_errors: list[Exception] = []
        self.states = ["SUCCESS"]  # popped per state() call; the last one repeats
        self.summary_result = MALICIOUS
        self.submitted: list[tuple[str, bytes, int, bool]] = []
        self.overview_calls = 0

    async def overview(self, sha256):
        self.overview_calls += 1
        if self.overview_error:
            raise self.overview_error
        return self.reports.get(sha256)

    async def submit_file(self, filename, data, environment_id, share_third_party=False):
        if self.submit_errors:
            raise self.submit_errors.pop(0)
        self.submitted.append((filename, data, environment_id, share_third_party))
        return {"job_id": f"ha-{len(self.submitted)}", "sha256": None}

    async def state(self, job_id):
        return self.states.pop(0) if len(self.states) > 1 else self.states[0]

    async def summary(self, job_id):
        return self.summary_result


class FakeVT:
    def __init__(self, known: dict | None = None, error: Exception | None = None):
        self.known, self.error = known, error

    async def file(self, sha256):
        if self.error:
            raise self.error
        return self.known


class Env:
    def __init__(self, settings, upload=SandboxUpload.ALWAYS, vt=None):
        settings.sandbox_upload = upload
        self.settings = settings
        self.gmail, self.store, self.ha = FakeGmail(), Store(":memory:"), FakeHA()
        self.provider = GmailProvider(self.gmail)
        analyzer = SandboxAnalyzer(self.ha, settings, self.store, "gmail", vt or FakeVT())
        self.scanner = Scanner(
            settings, self.provider, self.store, [*offline_analyzers(), analyzer]
        )
        self.worker = SandboxWorker(settings, self.provider, self.store, self.ha, self.scanner)

    def deliver(self, message_id="m1", data=PDF, name="report.pdf"):
        self.gmail.deliver(message_id, build_eml(subject="Q3 report", attachments=[(name, data)]))

    def poll(self):
        return asyncio.run(self.scanner.poll_once())

    def work(self):
        return asyncio.run(self.worker.run_once())

    def row(self, message_id="m1"):
        return self.store.get_row("gmail", message_id)

    def signals(self, message_id="m1"):
        return {f["signal"] for f in self.row(message_id).findings}


@pytest.fixture
def env(settings):
    return Env(settings)


# --- eligibility & verdict mapping ----------------------------


@pytest.mark.parametrize(
    ("name", "data", "expected"),
    [
        ("invoice.pdf", PDF, True),
        ("setup.exe", b"MZ\x90\x00", True),
        ("archive.zip", b"PK\x03\x04", True),
        ("photo.jpg", b"\xff\xd8\xff\xe0", False),
        ("logo.png", b"\x89PNG", False),
        ("notes.txt", b"hello", False),
        ("empty.pdf", b"", False),
    ],
)
def test_worth_sandboxing(name, data, expected):
    att = Attachment(filename=name, content_type="x", size=len(data), sha256="s", data=data)
    assert worth_sandboxing(att) is expected


@pytest.mark.parametrize(
    ("verdict", "signal", "points", "force"),
    [
        ("malicious", "attachments.sandbox_malicious", 60, True),
        ("suspicious", "attachments.sandbox_suspicious", 30, False),
        ("no specific threat", "attachments.sandbox_clean", 0, False),
        ("whitelisted", "attachments.sandbox_clean", 0, False),
        ("no verdict", "attachments.sandbox_no_verdict", 0, False),
    ],
)
def test_verdict_mapping(verdict, signal, points, force):
    finding = verdict_finding("a.exe", "sha", {**MALICIOUS, "verdict": verdict}, "sandbox run")
    assert (finding.signal, finding.points, finding.force_critical) == (signal, points, force)


# --- analyzer decisions ----------------------------


def test_existing_report_is_used_without_upload(env):
    env.ha.reports[PDF_SHA] = MALICIOUS
    env.deliver()
    env.poll()
    assert env.row().level is Level.CRITICAL
    assert "attachments.sandbox_malicious" in env.signals()
    assert env.store.jobs() == [] and env.ha.submitted == []


def test_unknown_file_is_queued_when_uploads_allowed(env):
    env.deliver()
    env.poll()
    [job] = env.store.jobs()
    assert (job.status, job.sha256, job.filename) == (JobStatus.PENDING, PDF_SHA, "report.pdf")
    assert "sandbox.pending" in env.signals()
    assert env.row().level is Level.CLEAN  # provisional
    assert env.ha.submitted == []  # queueing alone uploads nothing


def test_uploads_never(settings):
    env = Env(settings, upload=SandboxUpload.NEVER)
    env.deliver()
    env.poll()
    assert env.store.jobs() == []
    assert "sandbox.uploads_disabled" in env.signals()


def test_ask_mode_waits_for_approval(settings):
    env = Env(settings, upload=SandboxUpload.ASK)
    env.deliver()
    env.poll()
    [job] = env.store.jobs()
    assert job.status is JobStatus.AWAITING_APPROVAL
    assert "sandbox.awaiting_approval" in env.signals()
    env.work()
    assert env.ha.submitted == []  # nothing leaves without approval


def test_file_known_to_virustotal_is_not_uploaded(settings):
    env = Env(settings, vt=FakeVT(known={"malicious": 0}))
    env.deliver()
    env.poll()
    assert env.store.jobs() == []
    assert "sandbox.known_to_virustotal" in env.signals()


def test_unknown_virustotal_state_is_not_guessed(settings):
    env = Env(settings, vt=FakeVT(error=IntelUnavailable("quota")))
    env.deliver()
    env.poll()
    assert env.store.jobs() == []
    assert env.row().partial and "sandbox.unavailable" in env.signals()


def test_hybrid_analysis_lookup_failure_is_partial(env):
    env.ha.overview_error = IntelUnavailable("HA down")
    env.deliver()
    env.poll()
    assert env.store.jobs() == [] and env.row().partial


def test_too_large_dry_run_and_local_file(settings):
    settings.sandbox.max_file_mb = 1
    env = Env(settings)
    env.deliver(data=b"%PDF" + b"x" * (1024 * 1024 + 10))
    env.poll()
    assert "sandbox.too_large" in env.signals() and env.store.jobs() == []

    settings.dry_run = True
    env2 = Env(settings)
    env2.deliver()
    env2.poll()
    assert "sandbox.dry_run" in env2.signals() and env2.store.jobs() == []

    settings.dry_run = False
    local = make_email(attachments=[("report.pdf", PDF)])  # no provider id: a local .eml
    analyzer = SandboxAnalyzer(FakeHA(), settings, Store(":memory:"), "gmail", FakeVT())
    assert [f.signal for f in run(analyzer, local)] == ["sandbox.local_file"]


def test_finished_result_is_reused_for_the_same_file_in_other_emails(env):
    env.deliver("m1")
    env.poll()
    env.work()
    calls = env.ha.overview_calls
    env.deliver("m2")
    env.poll()
    assert env.row("m2").level is Level.CRITICAL
    assert env.ha.overview_calls == calls  # answered from our own finished job
    assert len(env.ha.submitted) == 1


# --- worker ----------------------------


def test_full_cycle_rescores_and_relabels(env):
    env.ha.states = ["IN_PROGRESS", "SUCCESS"]
    env.deliver()
    env.poll()
    assert "Phish/Clean" in env.gmail.label_names_of("m1")

    first = env.work()
    assert first.submitted == 1 and first.finished == 0
    [job] = env.store.jobs()
    assert job.status is JobStatus.SUBMITTED and job.sandbox_job_id == "ha-1"
    filename, data, environment, shared = env.ha.submitted[0]
    assert (filename, data, environment, shared) == ("report.pdf", PDF, 120, False)

    second = env.work()
    assert second.finished == 1 and second.rescored == 1
    [job] = env.store.jobs()
    assert (job.status, job.verdict, job.threat_score, job.applied) == (
        JobStatus.DONE,
        "malicious",
        100,
        True,
    )
    assert env.row().level is Level.CRITICAL and "attachments.sandbox_malicious" in env.signals()
    labels = env.gmail.label_names_of("m1")
    assert "Phish/Critical" in labels and "Phish/Clean" not in labels
    assert env.work().rescored == 0  # idempotent: nothing left to do


def test_clean_sandbox_verdict_keeps_email_clean(env):
    env.ha.summary_result = CLEAN
    env.deliver()
    env.poll()
    env.work()
    assert env.row().level is Level.CLEAN and "attachments.sandbox_clean" in env.signals()
    assert env.row().rechecks == 0


def test_approval_flow(settings):
    env = Env(settings, upload=SandboxUpload.ASK)
    env.deliver()
    env.poll()
    [job] = env.store.jobs()
    assert env.store.decide_jobs(True, [job.id]) == 1
    env.work()
    assert env.row().level is Level.CRITICAL


def test_rejected_job_is_never_uploaded_and_email_is_updated(settings):
    env = Env(settings, upload=SandboxUpload.ASK)
    env.deliver()
    env.poll()
    assert env.store.decide_jobs(False) == 1
    result = env.work()
    assert env.ha.submitted == [] and result.rescored == 1
    assert "sandbox.declined" in env.signals()


def test_switching_to_never_stops_queued_uploads(env):
    env.deliver()
    env.poll()
    env.settings.sandbox_upload = SandboxUpload.NEVER
    assert env.work().submitted == 0
    assert env.ha.submitted == []
    assert env.store.jobs()[0].status is JobStatus.PENDING


def test_upload_failure_is_postponed_then_retried(env):
    env.ha.submit_errors = [IntelUnavailable("rate limited")]
    env.deliver()
    env.poll()
    assert env.work().submitted == 0
    [job] = env.store.jobs()
    assert job.status is JobStatus.PENDING and "rate limited" in job.error
    assert env.work().submitted == 1


def test_job_fails_when_it_cannot_be_uploaded_in_time(env):
    env.ha.submit_errors = [IntelUnavailable("down")] * 10
    env.deliver()
    env.poll()
    [job] = env.store.jobs()
    env.store.update_job(job.id, created_at=utcnow() - timedelta(hours=2))
    result = env.work()
    assert result.failed == 1
    assert env.store.jobs()[0].status is JobStatus.FAILED
    assert "sandbox.failed" in env.signals()


def test_deleted_message_fails_job_without_error(env):
    env.deliver()
    env.poll()
    del env.gmail.messages_by_id["m1"]
    result = env.work()
    assert result.failed == 1
    [job] = env.store.jobs()
    assert job.status is JobStatus.FAILED and "deleted" in job.error and job.applied


def test_attachment_missing_from_message(env):
    env.deliver()
    env.poll()
    env.gmail.messages_by_id["m1"]["raw"] = build_eml(subject="edited, attachment removed")
    env.work()
    assert "no longer in the message" in env.store.jobs()[0].error


def test_sandbox_error_and_timeout(env):
    env.ha.states = ["ERROR"]
    env.deliver()
    env.poll()
    env.work()
    [job] = env.store.jobs()
    assert job.status is JobStatus.FAILED and "error" in job.error

    env.ha.states = ["IN_QUEUE"]
    env.deliver("m2", data=PDF + b" second file")
    env.poll()
    env.work()
    stuck = env.store.jobs(statuses=(JobStatus.SUBMITTED,))[0]
    env.store.update_job(stuck.id, submitted_at=utcnow() - timedelta(hours=2))
    env.work()
    assert env.store.get_job(stuck.id).status is JobStatus.FAILED
    assert "timed out" in env.store.get_job(stuck.id).error


def test_worker_idle_when_nothing_to_do(env):
    assert not env.worker.has_work()
    env.deliver()
    env.poll()
    assert env.worker.has_work()


def test_worker_preserves_recheck_count(env):
    env.deliver()
    env.poll()
    from sqlmodel import Session

    with Session(env.store.engine) as s:
        row = env.row()
        row.rechecks = 2
        s.add(row)
        s.commit()
    env.work()
    assert env.row().rechecks == 2


def test_run_forever_processes_and_stops(env):
    env.settings.sandbox.poll_interval_seconds = 10
    env.deliver()
    env.poll()

    async def go():
        stop = asyncio.Event()
        task = asyncio.create_task(env.worker.run_forever(stop))
        await asyncio.sleep(0.1)
        stop.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(go())
    assert env.row().level is Level.CRITICAL
