import pytest

from phishanalyzer.domains import (
    domain_label,
    domain_of_address,
    is_public_ip,
    levenshtein,
    looks_random,
    registrable_domain,
    same_org,
)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("mail.example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        # Private PSL suffix: the organisation is digitalfluxzone, not us.com.
        ("bafpfg.digitalfluxzone.us.com", "digitalfluxzone.us.com"),
        ("t.customermail.microsoft.com", "microsoft.com"),
        ("203.0.113.5", "203.0.113.5"),
        ("EXAMPLE.COM.", "example.com"),
        (None, None),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_domain_helpers():
    assert domain_of_address("User <x@Mail.Example.com>") == "mail.example.com"
    assert domain_of_address("not-an-address") is None
    assert domain_label("secure.paypal.co.uk") == "paypal"
    assert same_org("a.example.com", "b.example.com")
    assert not same_org("example.com", "example.net")


@pytest.mark.parametrize("label", ["mzpffvewq", "bafpfgwwinmwogj", "svbudsbhgyufdvghdfkshdigy"])
def test_looks_random_positive(label):
    assert looks_random(label)


@pytest.mark.parametrize(
    "label", ["customermail", "codymontana", "mailjet", "newsletter", "strengths", "microsoft"]
)
def test_looks_random_negative(label):
    assert not looks_random(label)


def test_levenshtein():
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("microsoft", "rnicrosoft") == 2
    assert levenshtein("", "abc") == 3


def test_is_public_ip():
    assert is_public_ip("51.210.183.120")
    assert not is_public_ip("10.0.0.1")
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("mail.example.com")
