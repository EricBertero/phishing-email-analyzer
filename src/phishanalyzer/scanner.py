"""Poll a mailbox, analyse new messages, store verdicts and label them."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass

from phishanalyzer.analyzers import Analyzer, offline_analyzers
from phishanalyzer.config import Settings
from phishanalyzer.models import Level
from phishanalyzer.parsing import parse_message
from phishanalyzer.pipeline import analyze_email
from phishanalyzer.providers import (
    AuthRequired,
    CursorExpired,
    MailProvider,
    MessageGone,
    ProviderError,
)
from phishanalyzer.storage import ScannedEmail, Store

log = logging.getLogger(__name__)

MAX_BACKOFF_SECONDS = 15 * 60


@dataclass
class PollResult:
    scanned: int = 0
    skipped: int = 0
    failed: int = 0
    cursor_advanced: bool = False


class Scanner:
    def __init__(
        self,
        settings: Settings,
        provider: MailProvider,
        store: Store,
        analyzers: list[Analyzer] | None = None,
    ):
        self.settings = settings
        self.provider = provider
        self.store = store
        self.analyzers = analyzers if analyzers is not None else offline_analyzers()

    async def _call(self, fn, *args):
        # Provider SDKs are synchronous; keep the event loop responsive.
        return await asyncio.to_thread(fn, *args)

    async def poll_once(self) -> PollResult:
        """Scan everything that arrived since the last poll.

        The cursor only advances when every new message was fetched, so a network blip
        never loses mail: the next poll lists the same changes and skips what's done.
        """
        name = self.provider.name
        await self.retry_labels()
        cursor = self.store.get_cursor(name)
        if cursor is None:
            # Take the cursor *before* listing, so mail arriving meanwhile isn't missed.
            new_cursor = await self._call(self.provider.current_cursor)
            ids = await self._call(self.provider.recent_message_ids, self.settings.backfill_count)
            log.info("First run: scanning the %d most recent inbox messages", len(ids))
        else:
            try:
                ids, new_cursor = await self._call(self.provider.changes_since, cursor)
            except CursorExpired:
                log.warning("Change history expired; resyncing recent messages")
                new_cursor = await self._call(self.provider.current_cursor)
                ids = await self._call(
                    self.provider.recent_message_ids, self.settings.backfill_count
                )

        result = PollResult()
        for message_id in ids:
            if self.store.is_scanned(name, message_id):
                result.skipped += 1
                continue
            try:
                await self.scan_message(message_id)
                result.scanned += 1
            except MessageGone:
                log.info("Message %s was deleted before it could be scanned", message_id)
            except AuthRequired:
                raise
            except ProviderError as exc:
                result.failed += 1
                log.warning("Could not fetch message %s: %s", message_id, exc)

        if result.failed == 0:
            self.store.set_cursor(name, new_cursor)
            result.cursor_advanced = True
        return result

    async def scan_message(self, message_id: str) -> ScannedEmail:
        raw = await self._call(self.provider.get_raw, message_id)
        try:
            email = parse_message(raw, provider_id=message_id)
            verdict = await analyze_email(email, self.settings, self.analyzers)
        except Exception as exc:
            # A message we can't analyse must not block the queue; record it and move on.
            log.exception("Failed to analyse message %s", message_id)
            return self.store.save_error(self.provider.name, message_id, repr(exc))

        row = self.store.save_result(self.provider.name, email, verdict)
        log.info(
            "[%s %d] %s: %s",
            verdict.level.upper(),
            verdict.score,
            email.from_addr,
            email.subject[:80],
        )
        await self._label(row)
        return row

    async def retry_labels(self) -> None:
        """Label results whose labelling failed earlier (or that were scanned in dry-run)."""
        if self.settings.dry_run:
            return
        for row in self.store.unlabeled(self.provider.name):
            await self._label(row)

    async def _label(self, row: ScannedEmail) -> None:
        if row.level is None or row.id is None:
            return
        level = Level(row.level)
        quarantine = self.settings.quarantine_critical and level is Level.CRITICAL
        if self.settings.dry_run:
            log.info("dry-run: would label %s as %s", row.provider_id, level.value)
            return
        try:
            await self._call(self.provider.apply_level, row.provider_id, level, quarantine)
        except MessageGone:
            self.store.mark_labeled(row.id)  # nothing left to label
        except AuthRequired:
            raise
        except ProviderError as exc:
            log.warning("Could not label %s (will retry): %s", row.provider_id, exc)
        else:
            self.store.mark_labeled(row.id)

    async def run_forever(self, stop: asyncio.Event | None = None) -> None:
        """Poll until `stop` is set. Backs off exponentially while the provider is failing."""
        stop = stop or asyncio.Event()
        delay = self.settings.poll_interval_seconds
        while not stop.is_set():
            try:
                result = await self.poll_once()
                if result.scanned or result.failed:
                    log.info("Poll: %d scanned, %d failed", result.scanned, result.failed)
                delay = (
                    self.settings.poll_interval_seconds
                    if result.failed == 0
                    else min(delay * 2, MAX_BACKOFF_SECONDS)
                )
            except AuthRequired:
                raise
            except ProviderError as exc:
                delay = min(delay * 2, MAX_BACKOFF_SECONDS)
                log.warning("Poll failed: %s (retrying in %ds)", exc, delay)
            except Exception:
                # A bug must not silently stop protection; keep polling, loudly.
                delay = min(delay * 2, MAX_BACKOFF_SECONDS)
                log.exception("Unexpected error while polling (retrying in %ds)", delay)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=delay)
