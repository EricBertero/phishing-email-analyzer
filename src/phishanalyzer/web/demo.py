"""Synthetic data for `phish serve --demo`: try the dashboard without a mailbox.

The emails are generated here and scored by the real offline analyzers, so every
verdict, finding and report on the demo dashboard is genuine output of this app. None of
them are real messages; all addresses use example or clearly fake domains.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage

from sqlmodel import Session

from phishanalyzer.config import Settings
from phishanalyzer.parsing import parse_message
from phishanalyzer.pipeline import analyze_email
from phishanalyzer.reporting.reporter import Reporter
from phishanalyzer.storage import JobStatus, ScannedEmail, Store

AUTH_RESULTS = {
    # Everything checks out.
    "pass": "mx.google.com; dkim=pass header.i=@{domain}; spf=pass "
    "smtp.mailfrom=bounce@{domain}; dmarc=pass (p=REJECT) header.from={domain}",
    # A throwaway domain with SPF/DKIM but no DMARC policy: common for low-effort phishing.
    "partial": "mx.google.com; dkim=pass header.i=@{domain}; spf=pass "
    "smtp.mailfrom=bounce@{domain}",
    # Spoofed: nothing authenticates.
    "fail": "mx.google.com; spf=softfail; dmarc=fail",
}


@dataclass(frozen=True)
class Template:
    weight: int
    sender: str
    subject: str
    text: str
    html: str | None = None
    attachments: tuple[tuple[str, bytes], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    auth: str = "pass"


# Weights give a realistic mix: mostly clean mail, some noise, a few serious threats.
TEMPLATES = [
    Template(
        30,
        "Northwind News <news@northwind.example.com>",
        "Your weekly digest",
        "Here are this week's top stories.",
        '<a href="https://northwind.example.com/read">Read</a>',
    ),
    Template(
        18,
        "Team Calendar <calendar@contoso.example.com>",
        "Reminder: planning meeting tomorrow",
        "See you at 10:00 in room 4.",
    ),
    Template(
        9,
        "Canada Giveaways <promo@giveaway-deals.example.com>",
        "Giveaways - last chance to win a truck",
        "Congratulations! Enter the giveaways now, it ends soon.",
        '<a href="https://bit.ly/3Q9pATZ">Enter</a>',
    ),
    Template(
        7,
        "Parcel Service <notify@parcel-status.example>",
        "Your parcel is on hold",
        "There is an outstanding payment of 1.99 EUR. Act now to release it.",
        '<a href="https://bit.ly/parcel-fee">Pay</a> '
        '<a href="https://storage.googleapis.com/parcel/fee.html">Details</a>',
        auth="partial",
    ),
    Template(
        5,
        "DocuSign <sign@docs-share-portal.example>",
        "Please review: Contract_2026.pdf",
        "Verify your email to open the shared document.",
        '<a href="https://docs-share.web.app/open">Review document</a>',
        auth="partial",
    ),
    Template(
        4,
        "PayPal Security <alert@paypal-secure-login.com>",
        "Urgent: your account has been suspended",
        "Your account has been suspended. Verify your identity within 24 hours.",
        '<a href="http://185.12.4.9/login">https://www.paypal.com/signin</a>',
        headers=(("Reply-To", "support@mail-help.example"),),
        auth="fail",
    ),
    Template(
        3,
        "Poste Italiane <avviso@poste-notifiche.example>",
        "Il tuo conto \u00e8 stato sospeso",
        "Il tuo conto \u00e8 stato sospeso. Verifica i tuoi dati entro 24 ore.",
        '<a href="https://storage.googleapis.com/bucket/poste.html">Accedi</a>',
        auth="fail",
    ),
    Template(
        3,
        "Accounts <billing@supplier-invoices.example>",
        "Outstanding invoice",
        "Please see the outstanding invoice attached.",
        attachments=(("Invoice_4471.pdf.exe", b"MZ\x90\x00demo-not-a-real-program"),),
        auth="fail",
    ),
    Template(
        2,
        "HR <hr@payroll-update.example>",
        "Updated salary review",
        "Open the attached document and enable content.",
        attachments=(("salary_review.docm", b"PK\x03\x04demo"),),
        auth="partial",
    ),
]


def _build(t: Template, n: int) -> bytes:
    msg = EmailMessage()
    domain = t.sender.rsplit("@", 1)[1].rstrip(">")
    if t.auth == "fail":
        msg["Received"] = (
            f"from unknown (host-{n}.dyn.example.net. [185.12.{n % 250}.{n % 200 + 1}]) "
            "by mx.google.com"
        )
    else:
        msg["Received"] = (
            f"from mail.{domain} (mail.{domain}. [52.10.20.{n % 250 + 1}]) by mx.google.com"
        )
    msg["Authentication-Results"] = AUTH_RESULTS[t.auth].format(domain=domain)
    for name, value in t.headers:
        msg[name] = value
    msg["From"] = t.sender
    msg["To"] = "you@example.com"
    msg["Subject"] = t.subject
    msg["Message-ID"] = f"<demo-{n}@{domain}>"
    msg.set_content(t.text)
    if t.html:
        msg.add_alternative(t.html, subtype="html")
    for filename, data in t.attachments:
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=filename)
    return msg.as_bytes()


async def seed(settings: Settings, store: Store, count: int = 90, days: int = 14) -> None:
    rng = random.Random(7)
    weights = [t.weight for t in TEMPLATES]
    now = datetime.now(UTC)
    reporter = Reporter(settings, store, None)
    for n in range(count):
        template = rng.choices(TEMPLATES, weights)[0]
        raw = _build(template, n)
        email = parse_message(raw, provider_id=f"demo-{n:03d}")
        verdict = await analyze_email(email, settings)
        row = store.save_result("demo", email, verdict)
        # Spread the mail over the period, more of it on weekdays.
        when = now - timedelta(days=rng.random() ** 1.3 * days, minutes=rng.randint(0, 600))
        with Session(store.engine) as session:
            db_row = session.get(ScannedEmail, row.id)
            db_row.scanned_at = when
            db_row.labeled = True
            session.add(db_row)
            session.commit()
        if verdict.level.value == "critical" and n % 3 == 0:
            await reporter.report("demo", email, verdict)
        if template.attachments and n % 2 == 0:
            att = email.attachments[0]
            status = JobStatus.AWAITING_APPROVAL if n % 4 == 0 else JobStatus.DONE
            job = store.enqueue_job(
                "demo", email.provider_id, att.sha256, att.filename, att.size, status
            )
            if status is JobStatus.DONE:
                store.update_job(
                    job.id,
                    verdict="malicious",
                    threat_score=100,
                    applied=True,
                    result={"verdict": "malicious", "threat_score": 100},
                )


def seed_sync(settings: Settings, store: Store) -> None:
    asyncio.run(seed(settings, store))
