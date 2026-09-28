"""In-memory stand-in for the googleapiclient Gmail service object."""

from __future__ import annotations

import base64
from typing import Any

import httplib2
from googleapiclient.errors import HttpError


def http_error(status: int) -> HttpError:
    return HttpError(httplib2.Response({"status": status}), b'{"error": "fake"}')


class Req:
    def __init__(self, fn):
        self.fn = fn

    def execute(self, num_retries: int = 0) -> Any:
        return self.fn()


class FakeGmail:
    def __init__(self, email_address: str = "me@gmail.com"):
        self.email_address = email_address
        self.history_id = 1000
        self.messages_by_id: dict[str, dict[str, Any]] = {}
        self.history: list[dict[str, Any]] = []
        self.labels: list[dict[str, Any]] = [
            {"id": "INBOX", "name": "INBOX"},
            {"id": "SPAM", "name": "SPAM"},
        ]
        self.expired_before = 0  # history ids below this raise 404
        self.fail_next: dict[str, int] = {}  # operation -> HTTP status to raise once
        self.page_size = 2
        self.calls: list[str] = []

    # --- test helpers ---------------------------------------------------------------
    def deliver(self, message_id: str, raw: bytes, labels: tuple[str, ...] = ("INBOX",)):
        self.history_id += 1
        self.messages_by_id[message_id] = {"raw": raw, "labelIds": list(labels)}
        self.history.append(
            {
                "id": str(self.history_id),
                "messagesAdded": [{"message": {"id": message_id, "labelIds": list(labels)}}],
            }
        )

    def label_names_of(self, message_id: str) -> set[str]:
        by_id = {lbl["id"]: lbl["name"] for lbl in self.labels}
        return {by_id.get(i, i) for i in self.messages_by_id[message_id]["labelIds"]}

    def _maybe_fail(self, op: str) -> None:
        self.calls.append(op)
        if op in self.fail_next:
            raise http_error(self.fail_next.pop(op))

    # --- API surface: service.users().<resource>().<method>(...).execute() -------------
    def users(self):
        return _Users(self)


class _Users:
    def __init__(self, gmail: FakeGmail):
        self.g = gmail

    def getProfile(self, userId):
        return Req(
            lambda: {"emailAddress": self.g.email_address, "historyId": str(self.g.history_id)}
        )

    def messages(self):
        return _Messages(self.g)

    def history(self):
        return _History(self.g)

    def labels(self):
        return _Labels(self.g)


class _Messages:
    def __init__(self, gmail: FakeGmail):
        self.g = gmail

    def list(self, userId, labelIds, maxResults, pageToken=None):
        def run():
            self.g._maybe_fail("messages.list")
            ids = [
                mid
                for mid, m in reversed(self.g.messages_by_id.items())
                if set(labelIds) <= set(m["labelIds"])
            ]
            start = int(pageToken or 0)
            page = ids[start : start + min(maxResults, self.g.page_size)]
            response: dict[str, Any] = {"messages": [{"id": i} for i in page]}
            if start + len(page) < len(ids):
                response["nextPageToken"] = str(start + len(page))
            return response

        return Req(run)

    def get(self, userId, id, format):
        def run():
            self.g._maybe_fail("messages.get")
            if id not in self.g.messages_by_id:
                raise http_error(404)
            raw = self.g.messages_by_id[id]["raw"]
            return {"id": id, "raw": base64.urlsafe_b64encode(raw).decode().rstrip("=")}

        return Req(run)

    def modify(self, userId, id, body):
        def run():
            self.g._maybe_fail("messages.modify")
            if id not in self.g.messages_by_id:
                raise http_error(404)
            labels = self.g.messages_by_id[id]["labelIds"]
            labels[:] = [x for x in labels if x not in body["removeLabelIds"]]
            labels += [x for x in body["addLabelIds"] if x not in labels]
            return {"id": id}

        return Req(run)


class _History:
    def __init__(self, gmail: FakeGmail):
        self.g = gmail

    def list(self, userId, startHistoryId, historyTypes, labelId, pageToken=None):
        def run():
            self.g._maybe_fail("history.list")
            if int(startHistoryId) < self.g.expired_before:
                raise http_error(404)
            records = [h for h in self.g.history if int(h["id"]) > int(startHistoryId)]
            start = int(pageToken or 0)
            page = records[start : start + self.g.page_size]
            response: dict[str, Any] = {"history": page, "historyId": str(self.g.history_id)}
            if start + len(page) < len(records):
                response["nextPageToken"] = str(start + len(page))
            return response

        return Req(run)


class _Labels:
    def __init__(self, gmail: FakeGmail):
        self.g = gmail

    def list(self, userId):
        return Req(lambda: {"labels": list(self.g.labels)})

    def create(self, userId, body):
        def run():
            self.g._maybe_fail("labels.create")
            label = {"id": f"Label_{len(self.g.labels)}", **body}
            self.g.labels.append(label)
            return label

        return Req(run)
