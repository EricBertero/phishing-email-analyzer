"""Background worker: upload queued attachments, poll the sandbox, re-score emails.

The database never holds attachment bytes. To upload a queued file the worker fetches
the message from the mailbox again and picks the attachment by its sha256, so the file
only exists in memory, only for the length of the upload.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from datetime import timedelta

from phishanalyzer.config import SandboxUpload, Settings
from phishanalyzer.intel.base import IntelUnavailable
from phishanalyzer.intel.hybrid_analysis import (
    STATE_DONE,
    STATE_ERROR,
    STATES_RUNNING,
    HybridAnalysisClient,
)
from phishanalyzer.parsing import parse_message
from phishanalyzer.providers import AuthRequired, MailProvider, MessageGone, ProviderError
from phishanalyzer.scanner import Scanner
from phishanalyzer.storage import (
    SETTLED_JOB_STATUSES,
    JobStatus,
    SandboxJob,
    Store,
)
from phishanalyzer.storage.db import utcnow

log = logging.getLogger(__name__)


@dataclass
class WorkerResult:
    submitted: int = 0
    finished: int = 0
    failed: int = 0
    rescored: int = 0


class SandboxWorker:
    def __init__(
        self,
        settings: Settings,
        provider: MailProvider,
        store: Store,
        client: HybridAnalysisClient,
        scanner: Scanner,
    ):
        self.settings = settings
        self.provider = provider
        self.store = store
        self.client = client
        self.scanner = scanner

    @property
    def _name(self) -> str:
        return self.provider.name

    def has_work(self) -> bool:
        """Cheap check so an idle worker doesn't wake the mailbox or the API."""
        jobs = self.store.jobs(self._name, (JobStatus.PENDING, JobStatus.SUBMITTED), limit=1)
        return bool(jobs) or bool(self._unapplied())

    def _unapplied(self) -> list[SandboxJob]:
        return self.store.jobs(self._name, SETTLED_JOB_STATUSES, only_unapplied=True)

    async def run_once(self) -> WorkerResult:
        result = WorkerResult()
        await self._submit_pending(result)
        await self._poll_submitted(result)
        await self._rescore(result)
        return result

    # --- upload -----------------------------------------------------------------------
    async def _submit_pending(self, result: WorkerResult) -> None:
        pending = self.store.jobs(self._name, (JobStatus.PENDING,))
        if not pending:
            return
        # Checked here as well as at queue time: switching the setting to "never" must stop
        # uploads that were queued earlier.
        if self.settings.sandbox_upload is SandboxUpload.NEVER or self.settings.dry_run:
            log.info("%d sandbox job(s) waiting; uploads are disabled right now", len(pending))
            return
        for job in pending:
            if self._expired(job.created_at):
                self._fail(job, "could not be uploaded in time", result)
                continue
            try:
                await self._submit(job, result)
            except IntelUnavailable as exc:
                log.warning("Sandbox upload of job %s postponed: %s", job.id, exc)
                self.store.update_job(job.id, error=str(exc))
            except MessageGone:
                self._fail(job, "the message was deleted before the upload", result)

    async def _submit(self, job: SandboxJob, result: WorkerResult) -> None:
        raw = await asyncio.to_thread(self.provider.get_raw, job.provider_id)
        attachment = next(
            (a for a in parse_message(raw).attachments if a.sha256 == job.sha256), None
        )
        if attachment is None:
            self._fail(job, "the attachment is no longer in the message", result)
            return
        limit = self.settings.sandbox.max_file_mb * 1024 * 1024
        if attachment.size > limit:
            self._fail(job, "the file is too large to sandbox", result)
            return
        env = self.settings.sandbox.environment_id
        submitted = await self.client.submit_file(
            attachment.filename or f"{job.sha256[:12]}.bin",
            attachment.data,
            env,
            self.settings.sandbox.share_third_party,
        )
        self.store.update_job(
            job.id,
            status=JobStatus.SUBMITTED,
            sandbox_job_id=submitted["job_id"],
            environment_id=env,
            submitted_at=utcnow(),
            error=None,
        )
        result.submitted += 1
        log.info("Submitted '%s' (job %s) to the sandbox", job.filename or job.sha256[:12], job.id)

    # --- poll -----------------------------------------------------------------------------
    async def _poll_submitted(self, result: WorkerResult) -> None:
        for job in self.store.jobs(self._name, (JobStatus.SUBMITTED,)):
            try:
                state = await self.client.state(job.sandbox_job_id or "")
                if state == STATE_DONE:
                    report = await self.client.summary(job.sandbox_job_id or "")
                    self.store.update_job(
                        job.id,
                        status=JobStatus.DONE,
                        finished_at=utcnow(),
                        verdict=report["verdict"],
                        threat_score=report["threat_score"],
                        result=report,
                        error=None,
                    )
                    result.finished += 1
                    log.info("Sandbox verdict for job %s: %s", job.id, report["verdict"])
                    continue
                if state == STATE_ERROR:
                    self._fail(job, "the sandbox reported an error", result)
                    continue
                if state not in STATES_RUNNING:
                    log.warning("Job %s: unexpected sandbox state %r", job.id, state)
            except IntelUnavailable as exc:
                log.warning("Could not poll sandbox job %s: %s", job.id, exc)
            if self._expired(job.submitted_at or job.created_at):
                self._fail(job, "the analysis timed out", result)

    # --- re-score -------------------------------------------------------------------------
    async def _rescore(self, result: WorkerResult) -> None:
        """Re-analyse each affected email once, with the sandbox outcome now available."""
        by_message: dict[str, list[SandboxJob]] = {}
        for job in self._unapplied():
            by_message.setdefault(job.provider_id, []).append(job)
        for provider_id, jobs in by_message.items():
            row = self.store.get_row(self._name, provider_id)
            try:
                await self.scanner.scan_message(provider_id, rechecks=row.rechecks if row else 0)
                result.rescored += 1
            except MessageGone:
                pass  # nothing left to update
            except AuthRequired:
                raise
            except ProviderError as exc:
                log.warning("Could not re-score %s yet: %s", provider_id, exc)
                continue
            for job in jobs:
                self.store.update_job(job.id, applied=True)

    # --- helpers ----------------------------------------------------------------------------
    def _expired(self, since) -> bool:
        return utcnow() - since > timedelta(minutes=self.settings.sandbox.timeout_minutes)

    def _fail(self, job: SandboxJob, reason: str, result: WorkerResult) -> None:
        log.warning("Sandbox job %s failed: %s", job.id, reason)
        self.store.update_job(job.id, status=JobStatus.FAILED, error=reason, finished_at=utcnow())
        result.failed += 1

    async def run_forever(self, stop: asyncio.Event | None = None) -> None:
        stop = stop or asyncio.Event()
        interval = self.settings.sandbox.poll_interval_seconds
        while not stop.is_set():
            try:
                if self.has_work():
                    await self.run_once()
            except AuthRequired:
                raise
            except Exception:
                log.exception("Sandbox worker error (will retry)")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=interval)
