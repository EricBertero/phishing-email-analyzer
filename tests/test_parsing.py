import hashlib

from conftest import FIXTURES, build_eml, make_email

from phishanalyzer.parsing import parse_file, parse_message
from phishanalyzer.parsing.forwarded import parse_forwarded
from phishanalyzer.parsing.received import origin_hop, parse_hop, parse_received
from phishanalyzer.parsing.urls import extract_urls, html_to_text


def test_parse_basic_fields():
    email = make_email(
        from_='"PayPal Service" <Service@PayPal.com>',
        headers=[("Reply-To", "help <x@other.net>"), ("Return-Path", "<bounce@paypal.com>")],
    )
    assert email.from_display == "PayPal Service"
    assert email.from_addr == "service@paypal.com"
    assert email.reply_to == "x@other.net"
    assert email.return_path == "bounce@paypal.com"
    assert email.to == ["me@gmail.com"]
    assert email.message_id == "<abc123@example.com>"
    assert email.date is not None and email.date.year == 2025
    assert email.sender_ip == "52.10.20.30"


def test_attachments_are_extracted_and_hashed():
    email = make_email(attachments=[("invoice.pdf", b"%PDF-1.7 hello")])
    [att] = email.attachments
    assert att.filename == "invoice.pdf"
    assert att.size == 14
    assert att.sha256 == hashlib.sha256(b"%PDF-1.7 hello").hexdigest()
    assert att.data == b"%PDF-1.7 hello"
    assert "invoice" not in email.text_body


def test_bad_charset_does_not_lose_body():
    raw = (
        b"From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n"
        b"Content-Type: text/plain; charset=made-up-charset\r\n\r\nHello caf\xc3\xa9\r\n"
    )
    assert "Hello" in parse_message(raw).text_body


def test_malformed_date_is_ignored():
    raw = b"From: a@example.com\r\nDate: not a date\r\nSubject: x\r\n\r\nbody\r\n"
    assert parse_message(raw).date is None


def test_html_links_keep_anchor_text_and_dedupe():
    html = """
      <style>.a{background:url(https://css.example/bg.png)}</style>
      <a href="https://evil.example/login">https://www.paypal.com</a>
      <a href="https://evil.example/login">again</a>
      <p>Visit www.example.org/page.</p>
      <form action="https://harvest.example/post"><input name=p></form>
    """
    urls = extract_urls("", html)
    by_url = {u.url: u for u in urls if u.source != "form"}
    assert by_url["https://evil.example/login"].display_text == "https://www.paypal.com"
    assert "http://www.example.org/page" in by_url
    assert [u.url for u in urls if u.source == "form"] == ["https://harvest.example/post"]
    # Style/script content is not visible text.
    assert "css.example" not in html_to_text(html)


def test_text_urls_strip_trailing_punctuation():
    urls = extract_urls("See (https://example.com/a?b=1). Or https://x.example/path, ok", "")
    assert [u.url for u in urls] == ["https://example.com/a?b=1", "https://x.example/path"]


def test_received_hop_variants():
    hop = parse_hop(
        "from sfdfasdwdew.com (syn-051-210-183-120.res.spectrum.com. [51.210.183.120]) "
        "by mx.google.com with ESMTPS id x"
    )
    assert hop.from_helo == "sfdfasdwdew.com"
    assert hop.from_rdns == "syn-051-210-183-120.res.spectrum.com"
    assert hop.from_ip == "51.210.183.120"
    assert hop.by_host == "mx.google.com"

    assert parse_hop("from unknown (HELO x) ([198.51.100.7]) by mx").from_ip == "198.51.100.7"
    assert parse_hop("from efianalytics.com (efianalytics.com. 216.244.76.116)").from_ip == (
        "216.244.76.116"
    )
    v6 = parse_hop("from mail.example.org (mail.example.org [IPv6:2001:db8::1]) by mx")
    assert v6.from_ip == "2001:db8::1"
    assert parse_hop("by 2002:adf:f18d:0:b0:390 with SMTP id h13; Sat").from_ip is None


def test_origin_hop_skips_internal_and_uses_topmost_public():
    hops = parse_received(
        [
            "by mx.google.com with SMTP id x",
            "from relay.internal (relay.internal [10.1.2.3]) by mx.corp.example",
            "from mta.sender.example (mta.sender.example. [52.1.2.3]) by relay.internal",
            # Below the trusted hop: written by the sender, possibly forged.
            "from forged.example (forged.example. [8.8.8.8]) by mta.sender.example",
        ]
    )
    origin = origin_hop(hops)
    assert origin is not None and origin.from_ip == "52.1.2.3"


def test_forwarded_gmail_english_and_italian():
    gmail = (
        "FYI\n---------- Forwarded message ---------\n"
        "From: Microsoft Rewards <MicrosoftRewards@customermail.microsoft.com>\n"
        "Date: Sat, Mar 29, 2025\nSubject: You won\nTo: <me@gmail.com>\n"
    )
    info = parse_forwarded(gmail)
    assert info.from_addr == "microsoftrewards@customermail.microsoft.com"
    assert info.from_display == "Microsoft Rewards"
    assert info.subject == "You won"

    italian = "---------- Messaggio inoltrato ---------\nDa: *Poste* <avviso@poste-it.xyz>\n"
    assert parse_forwarded(italian).from_addr == "avviso@poste-it.xyz"
    assert parse_forwarded("no forward here\nFrom: someone <a@b.com>") is None


def test_parse_real_fixtures():
    test1 = parse_file(FIXTURES / "test1.eml")
    assert test1.sender_ip == "51.210.183.120"
    assert test1.sender_rdns == "syn-051-210-183-120.res.spectrum.com"
    assert all("storage.googleapis.com" in u.url for u in test1.urls)

    test4 = parse_file(FIXTURES / "test4.eml")
    assert test4.forwarded is not None
    assert test4.forwarded.from_addr == "mvmsutrw@mzpffvewq.us"


def test_non_ascii_subject_roundtrip():
    subject = "Ciao — àèìòù"  # em dash + Italian accents
    assert parse_message(build_eml(subject=subject)).subject == subject
