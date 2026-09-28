import json

import pytest
from conftest import build_eml
from fake_gmail import FakeGmail

from phishanalyzer.models import Level
from phishanalyzer.providers import AuthRequired, CursorExpired, MessageGone, ProviderError
from phishanalyzer.providers.gmail import SCOPES, GmailProvider, load_credentials


@pytest.fixture
def gmail() -> FakeGmail:
    return FakeGmail()


@pytest.fixture
def provider(gmail) -> GmailProvider:
    return GmailProvider(gmail, label_prefix="Phish")


def test_account_and_cursor(gmail, provider):
    assert provider.account() == "me@gmail.com"
    assert provider.current_cursor() == "1000"


def test_recent_message_ids_oldest_first_across_pages(gmail, provider):
    for i in range(5):
        gmail.deliver(f"m{i}", b"x")
    gmail.deliver("spam1", b"x", labels=("SPAM",))
    assert provider.recent_message_ids(3) == ["m2", "m3", "m4"]
    assert provider.recent_message_ids(10) == ["m0", "m1", "m2", "m3", "m4"]
    assert provider.recent_message_ids(0) == []


def test_changes_since_paginates_and_filters(gmail, provider):
    cursor = provider.current_cursor()
    gmail.deliver("a", b"x")
    gmail.deliver("draft", b"x", labels=("DRAFT", "INBOX"))
    gmail.deliver("b", b"x")
    gmail.deliver("sent", b"x", labels=("SENT",))
    gmail.deliver("c", b"x")
    ids, new_cursor = provider.changes_since(cursor)
    assert ids == ["a", "b", "c"]
    assert new_cursor == str(gmail.history_id)
    assert provider.changes_since(new_cursor) == ([], new_cursor)


def test_expired_cursor(gmail, provider):
    gmail.expired_before = 5000
    with pytest.raises(CursorExpired):
        provider.changes_since("1")


def test_get_raw_roundtrip_and_missing(gmail, provider):
    raw = build_eml(subject="Hi")
    gmail.deliver("m1", raw)
    assert provider.get_raw("m1") == raw
    with pytest.raises(MessageGone):
        provider.get_raw("nope")


def test_http_errors_are_translated(gmail, provider):
    gmail.fail_next["history.list"] = 503
    with pytest.raises(ProviderError):
        provider.changes_since("1000")
    gmail.fail_next["history.list"] = 401
    with pytest.raises(AuthRequired):
        provider.changes_since("1000")


def test_apply_level_creates_labels_once_and_replaces_previous_verdict(gmail, provider):
    gmail.deliver("m1", b"x")
    provider.apply_level("m1", Level.SUSPICIOUS)
    names = {lbl["name"] for lbl in gmail.labels}
    assert {"Phish", "Phish/Clean", "Phish/Critical", "Phish/Suspicious"} <= names
    assert gmail.label_names_of("m1") == {"INBOX", "Phish/Suspicious"}

    # Rescored later: the old verdict label is swapped, not accumulated.
    provider.apply_level("m1", Level.CRITICAL)
    assert gmail.label_names_of("m1") == {"INBOX", "Phish/Critical"}
    assert gmail.calls.count("labels.create") == 6  # parent + 5 levels, created once


def test_existing_labels_are_reused(gmail):
    gmail.labels += [{"id": "L1", "name": "phish"}, {"id": "L2", "name": "Phish/High"}]
    provider = GmailProvider(gmail)
    gmail.deliver("m1", b"x")
    provider.apply_level("m1", Level.HIGH)
    assert "L2" in gmail.messages_by_id["m1"]["labelIds"]
    assert gmail.calls.count("labels.create") == 4  # parent and High already existed


def test_label_colour_rejected_falls_back_to_plain(gmail, provider):
    gmail.labels.append({"id": "P", "name": "Phish"})  # parent exists
    gmail.deliver("m1", b"x")
    gmail.fail_next["labels.create"] = 400  # first coloured label is rejected once
    provider.apply_level("m1", Level.LOW)
    assert "Phish/Low" in gmail.label_names_of("m1")
    uncoloured = [lbl for lbl in gmail.labels if lbl["name"] == "Phish/Clean"]
    assert uncoloured and "color" not in uncoloured[0]


def test_parent_label_failure_propagates(gmail, provider):
    gmail.deliver("m1", b"x")
    gmail.fail_next["labels.create"] = 500
    with pytest.raises(ProviderError):
        provider.apply_level("m1", Level.LOW)


def test_quarantine_removes_inbox(gmail, provider):
    gmail.deliver("m1", b"x")
    provider.apply_level("m1", Level.CRITICAL, quarantine=True)
    assert gmail.label_names_of("m1") == {"Phish/Critical"}


def test_load_credentials_requires_auth_when_non_interactive(tmp_path):
    with pytest.raises(AuthRequired, match="phish auth"):
        load_credentials(tmp_path / "credentials.json", tmp_path / "token.json", False)


def test_load_credentials_explains_missing_client_file(tmp_path):
    with pytest.raises(AuthRequired, match="Desktop app"):
        load_credentials(tmp_path / "credentials.json", tmp_path / "token.json", True)


def test_token_with_old_scopes_is_not_used(tmp_path):
    token = tmp_path / "token.json"
    token.write_text(
        json.dumps(
            {
                "token": "t",
                "refresh_token": "r",
                "client_id": "c",
                "client_secret": "s",
                "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
            }
        )
    )
    with pytest.raises(AuthRequired):
        load_credentials(tmp_path / "credentials.json", token, False)
    assert SCOPES == ["https://www.googleapis.com/auth/gmail.modify"]
