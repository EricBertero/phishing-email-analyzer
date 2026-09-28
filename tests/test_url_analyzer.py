import pytest
from conftest import make_email, run, signals

from phishanalyzer.analyzers.urls import UrlAnalyzer

urls = UrlAnalyzer()


def html_link(href: str, text: str) -> str:
    return f'<p><a href="{href}">{text}</a></p>'


def test_text_mismatch():
    email = make_email(html=html_link("https://evil.example/x", "https://www.paypal.com/signin"))
    assert "urls.text_mismatch" in signals(run(urls, email))


def test_matching_text_is_fine():
    email = make_email(html=html_link("https://www.paypal.com/x", "paypal.com"))
    assert "urls.text_mismatch" not in signals(run(urls, email))


def test_senders_own_click_tracker_is_fine():
    email = make_email(
        from_="Microsoft <news@microsoft.com>",
        html=html_link("https://t.customermail.microsoft.com/r/?id=1", "https://aka.ms/win"),
    )
    assert "urls.text_mismatch" not in signals(run(urls, email))


def test_plain_words_as_anchor_text_are_not_mismatches():
    email = make_email(html=html_link("https://evil.example/x", "Click here"))
    assert "urls.text_mismatch" not in signals(run(urls, email))


@pytest.mark.parametrize(
    ("href", "signal"),
    [
        ("http://185.12.4.9/login", "urls.ip_address"),
        ("https://bit.ly/3Q9pATZ", "urls.shortener"),
        ("https://storage.googleapis.com/bucket/page.html#x", "urls.abused_hosting"),
        ("https://my-login.web.app/", "urls.abused_hosting"),
        ("https://xn--pypal-4ve.com/", "urls.punycode"),
        ("https://www.paypal.com@evil.example/", "urls.userinfo"),
    ],
)
def test_host_checks(href, signal):
    assert signal in signals(run(urls, make_email(html=html_link(href, "open"))))


def test_normal_links_score_nothing():
    email = make_email(
        html=html_link("https://www.example.com/news", "Read more")
        + html_link("https://example.com/unsubscribe", "Unsubscribe")
    )
    assert signals(run(urls, email)) == set()
