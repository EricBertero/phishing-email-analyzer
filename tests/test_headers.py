import pytest
from conftest import make_email, run, signals

from phishanalyzer.analyzers.headers import HeaderAnalyzer, load_brands

headers = HeaderAnalyzer()


def test_brands_file_loads():
    brands = load_brands()
    assert "paypal.com" in brands["paypal"]
    assert "telepass" in brands


@pytest.mark.parametrize(
    "from_",
    [
        "Telepass <promo@digitalfluxzone.us.com>",
        "Your-Costco Gift Inside <a@mzpffvewq.us>",
        "PAYPAL Security <alert@account-check.example>",
        "Poste Italiane <avviso@notifiche-clienti.it>",
    ],
)
def test_brand_impersonation(from_):
    assert "headers.brand_impersonation" in signals(run(headers, make_email(from_=from_)))


@pytest.mark.parametrize(
    "from_",
    [
        "PayPal <service@paypal.com>",
        "Microsoft Rewards <microsoftrewards@customermail.microsoft.com>",
        "Amazon.it <conferma-spedizione@amazon.it>",
        "Tim Smith <tim@smith-family.example>",  # a person, not the TIM brand
        "Chase Johnson <chase@johnson.example>",
    ],
)
def test_no_impersonation_for_official_domains_or_people(from_):
    assert "headers.brand_impersonation" not in signals(run(headers, make_email(from_=from_)))


@pytest.mark.parametrize(
    "domain", ["paypa1.com", "rnicrosoft.com", "paypal-secure.com", "microsoftsupport.net"]
)
def test_lookalike_domains(domain):
    email = make_email(from_=f"Support <help@{domain}>")
    assert "headers.lookalike_domain" in signals(run(headers, email))


@pytest.mark.parametrize(
    "domain", ["pineapple.com", "officedepot.com", "paypal.com", "purchase.com", "example.com"]
)
def test_not_lookalike(domain):
    email = make_email(from_=f"Someone <x@{domain}>")
    assert "headers.lookalike_domain" not in signals(run(headers, email))


def test_display_name_spoof():
    email = make_email(from_='"billing@paypal.com" <x@evil.example>')
    assert "headers.display_name_spoof" in signals(run(headers, email))
    ok = make_email(from_='"news@example.com" <news@example.com>')
    assert "headers.display_name_spoof" not in signals(run(headers, ok))


def test_reply_to_mismatch():
    email = make_email(headers=[("Reply-To", "ceo.private@gmail.com")])
    assert "headers.reply_to_mismatch" in signals(run(headers, email))
    same = make_email(headers=[("Reply-To", "support@help.example.com")])
    assert "headers.reply_to_mismatch" not in signals(run(headers, same))


def test_random_domain_and_suspicious_tld():
    email = make_email(from_="Gift <a@bafpfgwwinmwogj.promo.xyz>")
    assert {"headers.random_domain", "headers.suspicious_tld"} <= signals(run(headers, email))
    assert "headers.random_domain" not in signals(run(headers, make_email()))


def test_dynamic_ip():
    email = make_email(
        authenticated=False,
        headers=[
            (
                "Received",
                "from x (syn-051-210-183-120.res.spectrum.com. [51.210.183.120]) by mx.google.com",
            )
        ],
    )
    assert "headers.dynamic_ip" in signals(run(headers, email))
    assert "headers.dynamic_ip" not in signals(run(headers, make_email()))


def test_forwarded_original_sender_is_checked():
    text = (
        "---------- Forwarded message ---------\n"
        "From: Netflix <billing@netflix-account-update.com>\nSubject: Payment failed\n"
    )
    email = make_email(from_="Me <me@gmail.com>", text=text)
    found = signals(run(headers, email))
    assert "headers.brand_impersonation" in found
    finding = next(f for f in run(headers, email) if f.signal == "headers.brand_impersonation")
    assert "original sender" in finding.message
