"""Sandbox verdicts for attachments, and queueing of files nobody has analysed yet.

For each attachment, in order of preference:

1. a finished sandbox run we already have (any email, same sha256);
2. this email's own queued job (pending / awaiting approval / submitted / failed);
3. an existing Hybrid Analysis report for the hash: a private lookup, no upload;
4. a file VirusTotal knows: its verdict is handled by the VirusTotal analyzer, and the
   file is *not* uploaded (it is already public knowledge, and we keep it private);
5. otherwise, and only if `sandbox_upload` allows it, queue the file for detonation.
   The verdict is provisional until the worker reports back and the email is re-scored.
"""

from __future__ import annotations

from typing import Any, Protocol

from phishanalyzer.analyzers.attachments import sniff
from phishanalyzer.config import SandboxUpload, Settings
from phishanalyzer.intel.base import IntelUnavailable
from phishanalyzer.intel.hybrid_analysis import HybridAnalysisClient
from phishanalyzer.intel.virustotal import VirusTotalClient
from phishanalyzer.models import Attachment, Email, Finding, Severity
from phishanalyzer.storage import JobStatus, SandboxJob, Store

MAX_ATTACHMENTS_PER_EMAIL = 5

# Analysis of images and plain text is pointless and would upload private content.
_SKIP_KINDS = {"png", "jpeg", "gif"}
_SKIP_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "txt", "csv", "ics", "vcf"}


class _Named(Protocol):
    filename: str | None


def worth_sandboxing(att: Attachment) -> bool:
    if att.size <= 0:
        return False
    extension = (
        (att.filename or "").rsplit(".", 1)[-1].lower() if "." in (att.filename or "") else ""
    )
    return sniff(att.data) not in _SKIP_KINDS and extension not in _SKIP_EXTENSIONS


def name_of(att: _Named, sha256: str) -> str:
    return att.filename or sha256[:12]


def verdict_finding(filename: str, sha256: str, result: dict[str, Any], source: str) -> Finding:
    """Turn a sandbox report (`verdict`, `threat_score`, ...) into a finding."""
    verdict = (result.get("verdict") or "no verdict").lower()
    score = result.get("threat_score")
    detail = f" (threat score {score}/100)" if score is not None else ""
    family = f", family {result['family']}" if result.get("family") else ""
    evidence = {"filename": filename, "sha256": sha256, "source": source, **result}
    if verdict == "malicious":
        return Finding(
            signal="attachments.sandbox_malicious",
            points=60,
            severity=Severity.CRITICAL,
            force_critical=True,
            message=f"The sandbox judged '{filename}' malicious{detail}{family}.",
            evidence=evidence,
        )
    if verdict == "suspicious":
        return Finding(
            signal="attachments.sandbox_suspicious",
            points=30,
            severity=Severity.HIGH,
            message=f"The sandbox judged '{filename}' suspicious{detail}{family}.",
            evidence=evidence,
        )
    if verdict in ("no specific threat", "whitelisted"):
        return Finding(
            signal="attachments.sandbox_clean",
            points=0,
            severity=Severity.INFO,
            message=f"The sandbox found no specific threat in '{filename}'{detail}. "
            "This is not a guarantee: malware can detect sandboxes.",
            evidence=evidence,
        )
    return Finding(
        signal="attachments.sandbox_no_verdict",
        points=0,
        severity=Severity.INFO,
        message=f"The sandbox produced no verdict for '{filename}'.",
        evidence=evidence,
    )


def _info(signal: str, message: str, **evidence: Any) -> Finding:
    return Finding(
        signal=signal, points=0, severity=Severity.INFO, message=message, evidence=evidence
    )


class SandboxAnalyzer:
    name = "sandbox"

    def __init__(
        self,
        client: HybridAnalysisClient,
        settings: Settings,
        store: Store | None = None,
        provider: str | None = None,
        virustotal: VirusTotalClient | None = None,
    ):
        self.client = client
        self.settings = settings
        self.store = store
        self.provider = provider
        self.virustotal = virustotal

    async def analyze(self, email: Email) -> list[Finding]:
        eligible = list({a.sha256: a for a in email.attachments if worth_sandboxing(a)}.values())
        findings: list[Finding] = []
        errors: list[IntelUnavailable] = []
        for att in eligible[:MAX_ATTACHMENTS_PER_EMAIL]:
            try:
                findings += await self._one(email, att)
            except IntelUnavailable as exc:
                errors.append(exc)
        if errors:
            findings.append(
                Finding(
                    signal="sandbox.unavailable",
                    points=0,
                    severity=Severity.INFO,
                    message=f"Sandbox lookups could not be completed: {errors[0]}",
                    evidence={"errors": sorted({str(e) for e in errors})[:5]},
                    unavailable=True,
                )
            )
        return findings

    async def _one(self, email: Email, att: Attachment) -> list[Finding]:
        sha, name = att.sha256, name_of(att, att.sha256)

        if self.store and (done := self.store.finished_job_by_sha(sha)) and done.result:
            return [verdict_finding(name, sha, done.result, "sandbox run")]

        own = self._own_job(email, sha)
        if own is not None:
            return [self._job_state_finding(own, name, sha)]

        if report := await self.client.overview(sha):
            return [verdict_finding(name, sha, report, "existing Hybrid Analysis report")]

        # Never upload what VirusTotal already knows; if we cannot tell, do not guess.
        if self.virustotal is not None and await self.virustotal.file(sha) is not None:
            return [
                _info(
                    "sandbox.known_to_virustotal",
                    f"'{name}' is already known to VirusTotal, so it was not uploaded to "
                    "the sandbox.",
                    filename=name,
                    sha256=sha,
                )
            ]
        return [self._queue(email, att, name)]

    def _own_job(self, email: Email, sha: str) -> SandboxJob | None:
        if self.store and self.provider and email.provider_id:
            return self.store.job_for(self.provider, email.provider_id, sha)
        return None

    def _job_state_finding(self, job: SandboxJob, name: str, sha: str) -> Finding:
        evidence = {"filename": name, "sha256": sha, "job_id": job.id, "status": job.status}
        match job.status:
            case JobStatus.AWAITING_APPROVAL:
                return _info(
                    "sandbox.awaiting_approval",
                    f"'{name}' is unknown to VirusTotal and Hybrid Analysis. It will only be "
                    f"uploaded to the sandbox after you approve it (`phish sandbox approve "
                    f"{job.id}`).",
                    **evidence,
                )
            case JobStatus.PENDING | JobStatus.SUBMITTED:
                return _info(
                    "sandbox.pending",
                    f"'{name}' is being analysed in the sandbox; this verdict is provisional "
                    "and will be updated when the analysis finishes.",
                    **evidence,
                )
            case JobStatus.REJECTED:
                return _info(
                    "sandbox.declined", f"'{name}' was not sandboxed: upload declined.", **evidence
                )
            case _:
                return _info(
                    "sandbox.failed",
                    f"The sandbox analysis of '{name}' did not complete"
                    + (f": {job.error}" if job.error else "."),
                    **evidence,
                )

    def _queue(self, email: Email, att: Attachment, name: str) -> Finding:
        sha = att.sha256
        evidence = {"filename": name, "sha256": sha}
        upload = self.settings.sandbox_upload
        if att.size > self.settings.sandbox.max_file_mb * 1024 * 1024:
            return _info(
                "sandbox.too_large",
                f"'{name}' is too large to sandbox (limit {self.settings.sandbox.max_file_mb} MB).",
                **evidence,
            )
        if upload is SandboxUpload.NEVER:
            return _info(
                "sandbox.uploads_disabled",
                f"'{name}' is unknown to VirusTotal and Hybrid Analysis. It was not "
                "sandboxed because uploads are disabled (`sandbox_upload: never`).",
                **evidence,
            )
        if not (self.store and self.provider and email.provider_id):
            return _info(
                "sandbox.local_file",
                f"'{name}' was not sandboxed: files from local .eml files are never uploaded.",
                **evidence,
            )
        if self.settings.dry_run:
            return _info(
                "sandbox.dry_run", f"dry-run: '{name}' would be queued for the sandbox.", **evidence
            )
        status = JobStatus.AWAITING_APPROVAL if upload is SandboxUpload.ASK else JobStatus.PENDING
        job = self.store.enqueue_job(
            self.provider, email.provider_id, att.sha256, att.filename, att.size, status
        )
        return self._job_state_finding(job, name, sha)
