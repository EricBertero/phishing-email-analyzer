"""Interface between the scanner and a mailbox (Gmail today; Outlook/IMAP later)."""

from __future__ import annotations

from typing import Protocol

from phishanalyzer.models import Level


class ProviderError(Exception):
    """A mailbox operation failed, probably transiently (network, quota, 5xx)."""


class AuthRequired(ProviderError):
    """No valid credentials; the user has to (re-)authorise the app."""


class CursorExpired(ProviderError):
    """The saved change cursor is too old; a full resync is needed."""


class MessageGone(ProviderError):
    """The message was deleted before it could be fetched."""


class MailProvider(Protocol):
    """Synchronous mailbox operations; the scanner runs them in a worker thread.

    A *cursor* is an opaque bookmark in the mailbox's change log (Gmail: historyId).
    """

    name: str

    def account(self) -> str: ...

    def current_cursor(self) -> str: ...

    def recent_message_ids(self, limit: int) -> list[str]:
        """Most recent inbox messages, oldest first."""
        ...

    def changes_since(self, cursor: str) -> tuple[list[str], str]:
        """Messages that arrived in the inbox after `cursor`, and the new cursor.

        Raises CursorExpired when the cursor is too old to resume from.
        """
        ...

    def get_raw(self, message_id: str) -> bytes: ...

    def apply_level(self, message_id: str, level: Level, quarantine: bool = False) -> None:
        """Label the message with its verdict (replacing any earlier verdict label)."""
        ...
