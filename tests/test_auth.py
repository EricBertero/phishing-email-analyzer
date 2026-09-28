from conftest import make_email, run, signals

from phishanalyzer.analyzers.auth import AuthAnalyzer, parse_auth_results

auth = AuthAnalyzer()


def with_auth(value: str, **kwargs):
    return make_email(authenticated=False, headers=[("Authentication-Results", value)], **kwargs)


def test_all_pass_scores_nothing():
    findings = run(auth, make_email())
    assert signals(findings) == set()
    assert {f.signal for f in findings} == {"auth.spf_pass", "auth.dkim_pass", "auth.dmarc_pass"}


def test_failures():
    email = with_auth(
        "mx.google.com; dkim=fail header.i=@example.com; spf=fail smtp.mailfrom=x@example.com; "
        "dmarc=fail (p=REJECT) header.from=example.com"
    )
    assert signals(run(auth, email)) == {"auth.spf_fail", "auth.dkim_fail", "auth.dmarc_fail"}


def test_missing_dmarc_and_softfail():
    email = with_auth("mx.google.com; spf=softfail smtp.mailfrom=x@example.com")
    assert signals(run(auth, email)) == {"auth.spf_softfail", "auth.dkim_none", "auth.dmarc_none"}


def test_dkim_pass_for_unrelated_domain_is_unaligned():
    email = with_auth(
        "mx; dkim=pass header.i=@esp-mailer.net; spf=pass; dmarc=none",
        from_="Shop <news@shop.example>",
    )
    assert "auth.dkim_unaligned" in signals(run(auth, email))


def test_dkim_pass_on_subdomain_is_aligned():
    email = with_auth(
        "mx; dkim=pass header.i=@mail.example.com; spf=pass; dmarc=pass",
        from_="news@example.com",
    )
    assert signals(run(auth, email)) == set()


def test_only_topmost_header_is_trusted():
    email = make_email(
        authenticated=False,
        headers=[
            ("Authentication-Results", "mx.google.com; spf=fail; dkim=fail; dmarc=fail"),
            # Injected by the sender further down: must be ignored.
            ("Authentication-Results", "evil; spf=pass; dkim=pass; dmarc=pass"),
        ],
    )
    assert "auth.dmarc_fail" in signals(run(auth, email))


def test_received_spf_fallback():
    email = make_email(
        authenticated=False, headers=[("Received-SPF", "fail (domain does not designate)")]
    )
    assert "auth.spf_fail" in signals(run(auth, email))


def test_no_auth_headers_is_informational():
    findings = run(auth, make_email(authenticated=False))
    assert [f.signal for f in findings] == ["auth.no_results"]
    assert findings[0].points == 0


def test_parse_auth_results_multiple_dkim():
    results = parse_auth_results(
        "mx.google.com; dkim=pass header.i=@a.com; dkim=pass header.i=@b.com; spf=pass; "
        "dmarc=pass (p=NONE) header.from=a.com"
    )
    assert [r for r, _ in results["dkim"]] == ["pass", "pass"]
    assert results["dmarc"][0][0] == "pass"
