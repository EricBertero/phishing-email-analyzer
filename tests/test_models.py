from phishanalyzer.models import Attachment, Email


def test_header_lookup_is_case_insensitive():
    email = Email(
        headers=[
            ("Received", "from a.example"),
            ("received", "from b.example"),
            ("Subject", "Hi"),
        ]
    )
    assert email.header("SUBJECT") == "Hi"
    assert email.header("X-Missing") is None
    assert email.header_all("Received") == ["from a.example", "from b.example"]


def test_attachment_bytes_not_serialised():
    att = Attachment(
        filename="a.exe",
        content_type="application/octet-stream",
        size=3,
        sha256="x",
        data=b"MZ\x90",
    )
    assert "data" not in att.model_dump()
    assert "MZ" not in repr(att)
