import io
import zipfile

import pytest
from conftest import make_email, run, signals

from phishanalyzer.analyzers.attachments import AttachmentAnalyzer, sniff

attachments = AttachmentAnalyzer()

PE = b"MZ\x90\x00" + b"\x00" * 60
PDF = b"%PDF-1.7\n1 0 obj\n"
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64


def zip_bytes(entries: dict[str, bytes], encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if encrypted:
        # zipfile can't write encrypted archives; set the "encrypted" general-purpose flag
        # in the local and central headers instead. Content is irrelevant to the check.
        for sig, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = raw.find(sig)
            while pos != -1:
                raw[pos + flag_offset] |= 0x1
                pos = raw.find(sig, pos + 4)
    return bytes(raw)


def scan(filename: str, data: bytes) -> set[str]:
    return signals(run(attachments, make_email(attachments=[(filename, data)])))


def test_sniff():
    assert sniff(PE) == "pe"
    assert sniff(PDF) == "pdf"
    assert sniff(OLE) == "ole"
    assert sniff(b"hello") is None


def test_clean_pdf():
    assert scan("invoice.pdf", PDF) == set()


@pytest.mark.parametrize("name", ["setup.exe", "run.JS", "photo.scr", "doc.iso", "x.lnk"])
def test_dangerous_extensions(name):
    assert "attachments.dangerous_type" in scan(name, b"whatever")


def test_executable_content_under_innocent_name():
    found = scan("invoice.pdf", PE)
    assert {"attachments.dangerous_type", "attachments.type_mismatch"} <= found


def test_double_extension():
    assert {"attachments.double_extension", "attachments.dangerous_type"} <= scan(
        "Invoice.PDF.exe", PE
    )
    assert "attachments.double_extension" not in scan("report.final.pdf", PDF)


def test_macros():
    assert "attachments.macro" in scan("orders.xlsm", zip_bytes({"[Content_Types].xml": b""}))
    docx_with_vba = zip_bytes({"word/document.xml": b"", "word/vbaProject.bin": b"x"})
    assert "attachments.macro" in scan("letter.docx", docx_with_vba)
    ole_with_vba = OLE + "_VBA_PROJECT".encode("utf-16-le")
    assert "attachments.macro" in scan("old.doc", ole_with_vba)
    assert "attachments.macro" not in scan("plain.docx", zip_bytes({"word/document.xml": b""}))


def test_html_and_svg_attachments():
    assert "attachments.html" in scan("Secure_Message.html", b"<html></html>")
    assert "attachments.html" in scan("voicemail.svg", b"<svg></svg>")


def test_zip_with_executable_inside():
    assert "attachments.archive_dangerous" in scan("docs.zip", zip_bytes({"a/invoice.exe": PE}))
    assert scan("photos.zip", zip_bytes({"a.jpg": b"\xff\xd8\xff"})) == set()


def test_encrypted_zip():
    assert "attachments.encrypted_archive" in scan("secure.zip", zip_bytes({"a.txt": b"x"}, True))


def test_other_archives_are_uninspectable():
    assert "attachments.archive_uninspectable" in scan("files.rar", b"Rar!\x1a\x07\x00")


def test_corrupt_zip_does_not_crash():
    assert "attachments.type_mismatch" not in scan("broken.zip", b"PK\x03\x04garbage")
