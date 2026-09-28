"""Gmail via the Gmail API: OAuth, History API polling and verdict labels."""

from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import Any

import httplib2
from google.auth.exceptions import RefreshError, TransportError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from phishanalyzer.config import Settings
from phishanalyzer.models import Level
from phishanalyzer.providers.base import AuthRequired, CursorExpired, MessageGone, ProviderError

log = logging.getLogger(__name__)

# gmail.modify covers reading messages, managing labels and changing a message's labels.
# The app never sends or permanently deletes mail.
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# (background, text) from Gmail's fixed label palette.
LABEL_COLORS = {
    Level.CLEAN: ("#16a766", "#ffffff"),
    Level.LOW: ("#a4c2f4", "#000000"),
    Level.SUSPICIOUS: ("#fad165", "#000000"),
    Level.HIGH: ("#ffad47", "#000000"),
    Level.CRITICAL: ("#cc3a21", "#ffffff"),
}


def load_credentials(credentials_path: Path, token_path: Path, interactive: bool) -> Credentials:
    """Load the saved OAuth token, refreshing it or (if interactive) running the browser flow."""
    creds: Credentials | None = None
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path))
        if not creds.has_scopes(SCOPES):
            creds = None  # token from an older version with different scopes
    if creds and creds.valid:
        return creds
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
        except RefreshError:
            log.warning("Saved Gmail token was revoked or expired")
        else:
            token_path.write_text(creds.to_json(), encoding="utf-8")
            return creds

    if not interactive:
        raise AuthRequired("Gmail is not authorised. Run `phish auth` first.")
    if not credentials_path.exists():
        raise AuthRequired(
            f"{credentials_path} not found. Create an OAuth client ID of type 'Desktop app' in "
            "Google Cloud Console (APIs & Services > Credentials), download its JSON and save "
            "it there."
        )
    flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), SCOPES)
    creds = flow.run_local_server(port=0, open_browser=True)
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(creds.to_json(), encoding="utf-8")
    return creds


class GmailProvider:
    name = "gmail"

    def __init__(self, service: Any, label_prefix: str = "Phish"):
        self._service = service
        self._label_prefix = label_prefix
        self._label_ids: dict[Level, str] | None = None

    @classmethod
    def from_settings(cls, settings: Settings, interactive: bool = False) -> GmailProvider:
        creds = load_credentials(
            settings.paths.gmail_credentials, settings.paths.gmail_token, interactive
        )
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        return cls(service, settings.label_prefix)

    @property
    def _users(self) -> Any:
        return self._service.users()

    def _execute(self, request: Any, not_found: type[ProviderError] = ProviderError) -> Any:
        try:
            return request.execute(num_retries=3)
        except HttpError as exc:
            status = exc.resp.status
            if status == 404:
                raise not_found(str(exc)) from exc
            if status == 401:
                raise AuthRequired("Gmail rejected the credentials. Run `phish auth`.") from exc
            raise ProviderError(f"Gmail API error {status}: {exc.reason}") from exc
        except RefreshError as exc:
            raise AuthRequired("Gmail token was revoked. Run `phish auth`.") from exc
        except (OSError, TransportError, httplib2.HttpLib2Error) as exc:
            raise ProviderError(f"Network error talking to Gmail: {exc}") from exc

    def account(self) -> str:
        return self._execute(self._users.getProfile(userId="me"))["emailAddress"]

    def current_cursor(self) -> str:
        return str(self._execute(self._users.getProfile(userId="me"))["historyId"])

    def recent_message_ids(self, limit: int) -> list[str]:
        ids: list[str] = []
        page_token = None
        while len(ids) < limit:
            response = self._execute(
                self._users.messages().list(
                    userId="me",
                    labelIds=["INBOX"],
                    maxResults=min(limit - len(ids), 500),
                    pageToken=page_token,
                )
            )
            ids += [m["id"] for m in response.get("messages", [])]
            page_token = response.get("nextPageToken")
            if not page_token:
                break
        return list(reversed(ids[:limit]))  # the API returns newest first

    def changes_since(self, cursor: str) -> tuple[list[str], str]:
        ids: dict[str, None] = {}  # ordered set
        new_cursor, page_token = cursor, None
        while True:
            response = self._execute(
                self._users.history().list(
                    userId="me",
                    startHistoryId=cursor,
                    historyTypes=["messageAdded"],
                    labelId="INBOX",
                    pageToken=page_token,
                ),
                not_found=CursorExpired,
            )
            for record in response.get("history", []):
                for added in record.get("messagesAdded", []):
                    message = added["message"]
                    labels = set(message.get("labelIds", []))
                    if "INBOX" in labels and "DRAFT" not in labels:
                        ids[message["id"]] = None
            new_cursor = str(response.get("historyId", new_cursor))
            page_token = response.get("nextPageToken")
            if not page_token:
                return list(ids), new_cursor

    def get_raw(self, message_id: str) -> bytes:
        response = self._execute(
            self._users.messages().get(userId="me", id=message_id, format="raw"),
            not_found=MessageGone,
        )
        raw = response["raw"]
        return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))

    def apply_level(self, message_id: str, level: Level, quarantine: bool = False) -> None:
        label_ids = self._ensure_labels()
        remove = [label for lvl, label in label_ids.items() if lvl != level]
        if quarantine:
            remove.append("INBOX")
        self._execute(
            self._users.messages().modify(
                userId="me",
                id=message_id,
                body={"addLabelIds": [label_ids[level]], "removeLabelIds": remove},
            ),
            not_found=MessageGone,
        )

    def label_name(self, level: Level) -> str:
        return f"{self._label_prefix}/{level.value.title()}"

    def _ensure_labels(self) -> dict[Level, str]:
        """Find or create `Phish` and `Phish/<Level>` labels; cached after the first call."""
        if self._label_ids is not None:
            return self._label_ids
        response = self._execute(self._users.labels().list(userId="me"))
        existing = {lbl["name"].lower(): lbl["id"] for lbl in response.get("labels", [])}
        if self._label_prefix.lower() not in existing:
            self._create_label(self._label_prefix, None)

        ids = {}
        for level in Level:
            name = self.label_name(level)
            ids[level] = existing.get(name.lower()) or self._create_label(name, LABEL_COLORS[level])
        self._label_ids = ids
        return ids

    def _create_label(self, name: str, color: tuple[str, str] | None) -> str:
        body: dict[str, Any] = {
            "name": name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        }
        if color:
            body["color"] = {"backgroundColor": color[0], "textColor": color[1]}
        try:
            created = self._execute(self._users.labels().create(userId="me", body=body))
        except ProviderError:
            if not color:
                raise
            # Gmail only accepts palette colours; never fail labelling over cosmetics.
            body.pop("color")
            created = self._execute(self._users.labels().create(userId="me", body=body))
        log.info("Created Gmail label %s", name)
        return created["id"]
