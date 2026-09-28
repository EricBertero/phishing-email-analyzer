"""Social-engineering language in the subject and body (English and Italian)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from phishanalyzer.models import Email, Finding, Severity
from phishanalyzer.parsing.urls import html_to_text


@dataclass(frozen=True)
class Category:
    signal: str
    points: int
    severity: Severity
    description: str
    patterns: tuple[str, ...]


# Each category scores once, however many of its phrases appear. Phrases, not single
# words: "account" alone is in every newsletter, "your account has been suspended" isn't.
CATEGORIES = (
    Category(
        "content.credential_request",
        15,
        Severity.MEDIUM,
        "asks you to verify, unlock or update account or payment details",
        (
            r"verify your (?:account|identity|email|information|details)",
            r"confirm your (?:account|identity|password|details|information)",
            r"(?:account|mailbox) (?:has been |was |is |will be )?"
            r"(?:suspended|locked|limited|disabled|restricted|deactivated|closed)",
            r"unusual (?:sign[- ]?in|login|activity)",
            r"password (?:expires|will expire|has expired|expired)",
            r"update your (?:payment|billing|account|card) (?:information|details|method)",
            r"re-?enter your (?:password|credentials)",
            r"verifica(?:re)? (?:il tuo |la tua |i tuoi )?(?:account|identit[àa]|dati)",
            r"conferma(?:re)? (?:il tuo |la tua |i tuoi )?(?:account|identit[àa]|dati|password)",
            r"(?:account|conto|carta) (?:[èe] stat[oa] |verr[àa] )?"
            r"(?:sospes[oa]|bloccat[oa]|limitat[oa]|disattivat[oa])",
            r"aggiorna(?:re)? (?:i tuoi |i )?dati",
            r"accesso (?:insolito|sospetto|non autorizzato)",
        ),
    ),
    Category(
        "content.urgency",
        8,
        Severity.LOW,
        "pressures you to act quickly",
        (
            r"\burgent\b",
            r"\bimmediately\b",
            r"within (?:24|48|72) hours",
            r"act now",
            r"ends soon",
            r"last chance",
            r"expires? (?:today|soon|in \d+)",
            r"final (?:notice|warning|reminder)",
            r"don[’']?t miss out",
            r"\burgente\b",
            r"\bimmediatamente\b",
            r"entro (?:24|48|72) ore",
            r"ultima possibilit[àa]",
            r"scade (?:oggi|a breve|presto)",
            r"ultimo avviso",
        ),
    ),
    Category(
        "content.prize_lure",
        10,
        Severity.LOW,
        "promises a prize, gift or reward",
        (
            r"you(?:[’']ve| have)? (?:won|been selected)",
            r"\bcongratulations\b",
            r"claim your (?:prize|reward|gift|free)",
            r"\b(?:lucky|grand prize) (?:winner|few)\b",
            r"free gift",
            r"\bgiveaways?\b",
            r"hai vinto",
            r"\bcongratulazioni\b",
            r"sei stat[oa] selezionat[oa]",
            r"\b(?:ritira|riscatta) (?:il tuo |il )?(?:premio|regalo)",
            r"\bvincitore\b",
        ),
    ),
    Category(
        "content.payment_lure",
        10,
        Severity.MEDIUM,
        "talks about payments, invoices, gift cards or crypto",
        (
            r"wire transfer",
            r"gift ?cards?",
            r"\bbitcoin\b|\bbtc wallet\b|\bcrypto(?:currency)? wallet\b",
            r"payment (?:failed|declined|was unsuccessful)",
            r"outstanding (?:invoice|balance|payment)",
            r"refund (?:is )?(?:pending|available)",
            r"\bbonifico\b",
            r"pagamento (?:non riuscito|rifiutato|in sospeso)",
            r"fattura (?:in sospeso|scaduta|non pagata)",
            r"rimborso (?:disponibile|in attesa)",
        ),
    ),
)

_COMPILED = [(c, re.compile("|".join(f"(?:{p})" for p in c.patterns), re.I)) for c in CATEGORIES]


class ContentAnalyzer:
    name = "content"

    async def analyze(self, email: Email) -> list[Finding]:
        text = "\n".join([email.subject, email.text_body or html_to_text(email.html_body)])
        findings: list[Finding] = []
        for category, regex in _COMPILED:
            matches = sorted({m.group(0).lower() for m in regex.finditer(text)})
            if matches:
                findings.append(
                    Finding(
                        signal=category.signal,
                        points=category.points,
                        severity=category.severity,
                        message=f"The message {category.description}.",
                        evidence={"phrases": matches[:10]},
                    )
                )

        forms = [u for u in email.urls if u.source == "form"]
        if forms:
            findings.append(
                Finding(
                    signal="content.html_form",
                    points=20,
                    severity=Severity.HIGH,
                    message="The email contains an HTML form. Legitimate senders never ask "
                    "you to type data into an email.",
                    evidence={"actions": [f.url for f in forms]},
                )
            )
        return findings
