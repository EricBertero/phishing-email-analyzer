import pytest
from conftest import make_email, run, signals

from phishanalyzer.analyzers.content import ContentAnalyzer
from phishanalyzer.analyzers.spam import SpamHeaderAnalyzer

content = ContentAnalyzer()
spam = SpamHeaderAnalyzer()


@pytest.mark.parametrize(
    ("text", "signal"),
    [
        ("Your account has been suspended. Verify your identity.", "content.credential_request"),
        ("Il tuo account è stato sospeso, verifica i tuoi dati.", "content.credential_request"),
        ("Please respond within 24 hours or lose access.", "content.urgency"),
        ("Rispondi entro 24 ore!", "content.urgency"),
        ("Congratulations! You have won an iPhone.", "content.prize_lure"),
        ("Hai vinto un kit di emergenza", "content.prize_lure"),
        ("Please buy gift cards for the CEO.", "content.payment_lure"),
        ("Il pagamento non riuscito, effettua un bonifico.", "content.payment_lure"),
    ],
)
def test_phrases(text, signal):
    assert signal in signals(run(content, make_email(text=text)))


def test_ordinary_business_words_do_not_score():
    text = (
        "Hi team, the account manager will send the invoice and billing update for your "
        "subscription order. Security and privacy matter to our customers. Login details "
        "for the dashboard are in the portal."
    )
    assert signals(run(content, make_email(subject="Monthly update", text=text))) == set()


def test_each_category_scores_once():
    findings = run(content, make_email(text="Urgent! Act now! Last chance! Immediately!"))
    urgency = [f for f in findings if f.signal == "content.urgency"]
    assert len(urgency) == 1
    assert len(urgency[0].evidence["phrases"]) >= 3


def test_subject_and_html_only_body_are_scanned():
    email = make_email(subject="Final notice", text=None, html="<p>Hai vinto!</p>")
    assert {"content.urgency", "content.prize_lure"} <= signals(run(content, email))


def test_html_form():
    html = '<form action="https://x.example/p"><input type=password></form>'
    assert "content.html_form" in signals(run(content, make_email(html=html)))


@pytest.mark.parametrize(
    "hdrs",
    [
        [("X-Spam-Status", "Yes, score=7.1 required=5.0 tests=BAYES_99")],
        [("X-Spam-Flag", "YES")],
        [("X-Spam-Score", "9.3")],
        [("X-Forefront-Antispam-Report", "CIP:1.2.3.4;CTRY:US;SCL:6;SRV:;")],
        [("X-MS-Exchange-Organization-SCL", "5")],
    ],
)
def test_spam_headers_positive(hdrs):
    assert signals(run(spam, make_email(headers=hdrs))) & {
        "spam.filter_flagged",
        "spam.exchange_scl",
    }


@pytest.mark.parametrize(
    "hdrs",
    [
        [("X-Spam-Status", "No, score=-1.2 required=5.0")],
        [("X-MS-Exchange-Organization-SCL", "-1")],
        [("X-Forefront-Antispam-Report", "SCL:1;")],
        [],
    ],
)
def test_spam_headers_negative(hdrs):
    assert signals(run(spam, make_email(headers=hdrs))) == set()
