# Phishing Email Analyzer

Watches your inbox and scores every incoming email for phishing risk. It combines
several signals: authentication results (SPF/DKIM/DMARC), header anomalies, a spam score,
URL and IP/hostname reputation, and attachment analysis (file type, VirusTotal, and
Hybrid Analysis sandboxing). Each email gets a Gmail label (`Phish/Clean` …
`Phish/Critical`). Critical cases also get an HTML/PDF report with an AI-written summary.

> **Status: early rebuild.** This started as a hackathon project and is being rewritten
> as a proper service. The original code lives in [`legacy/`](legacy/) until it is fully ported.

## Roadmap

- [x] **1. Foundation**: package layout, config, core models, CLI, CI
- [x] **2. Offline core**: email parser and static analyzers, scoring, `phish scan-eml`
- [x] **3. Gmail**: OAuth, History API polling, labels, SQLite storage
- [ ] **4. Threat intel**: URLhaus, AbuseIPDB, Spamhaus DQS, VirusTotal
- [ ] **5. Sandbox**: Hybrid Analysis detonation with async re-scoring
- [ ] **6. Reports**: HTML/PDF plus a Claude-written summary for Critical emails
- [ ] **7. Dashboard**: FastAPI web UI

## Setup

Requires Python 3.12+.

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows; use `source .venv/bin/activate` elsewhere
pip install -e ".[dev]"
```

Configure:

1. `cp .env.example .env` and add the API keys you have. Every integration is optional,
   and a missing key simply disables that check.
2. Optionally, `cp config.example.yaml config.yaml` to tune thresholds, weights and polling.
3. Run `phish config` to see the effective configuration and which integrations are active.

## Watching Gmail

One-time setup:

1. In [Google Cloud Console](https://console.cloud.google.com/), create a project and
   enable the **Gmail API**.
2. Configure the **OAuth consent screen** (External, in testing mode), then add your own
   Gmail address as a test user.
3. Under **Credentials**, create an **OAuth client ID** of type **Desktop app**. Download
   the JSON and save it as `credentials.json` in the project folder.
4. Run `phish auth`. A browser window opens for you to sign in and approve access, and
   the token is saved to `token.json`.

The app asks only for the `gmail.modify` scope, which lets it read mail and change
labels. It never sends or deletes mail.

```bash
phish run --dry-run --once   # scan the latest emails once, change nothing in Gmail
phish run                    # keep watching; label new mail every poll_interval_seconds
phish recent                 # verdicts stored in data/phishanalyzer.db
phish recent --level critical
```

On the first run it scans the `backfill_count` most recent inbox messages. After that it
reads Gmail's change history, so only new mail is scanned, and restarts don't rescan old
mail. Each message gets one of the labels `Phish/Clean`, `Phish/Low`, `Phish/Suspicious`,
`Phish/High` or `Phish/Critical`. Set `quarantine_critical: true` to also move Critical
mail out of the inbox. If Gmail can't be reached, nothing is skipped: the scanner backs
off and resumes from where it stopped. The database stores only headers, scores and
findings, never message bodies or attachments.

## Scanning files

Analyse saved emails (`.eml`: in Gmail, use ⋮ → *Download message*). Nothing is sent
anywhere:

```bash
phish scan-eml suspicious.eml            # score breakdown
phish scan-eml *.eml --verbose           # include passed checks
phish scan-eml suspicious.eml --json     # machine-readable
```

Forwarded emails work too: the original sender in the forwarded block is analysed as well.

### Checks

| Area | What it looks at |
|---|---|
| Authentication | SPF, DKIM (and alignment with From), DMARC, from the recipient server's `Authentication-Results` |
| Sender identity | brand impersonation in the display name, lookalike domains (`paypa1`, `paypal-secure`), display name showing another address, Reply-To to another organisation, machine-generated domains, abused TLDs, punycode |
| Origin | real sending IP taken from the trusted `Received` hop; residential/dynamic IPs |
| Spam filters | SpamAssassin/rspamd `X-Spam-*` and Exchange SCL verdicts (spam-positive only) |
| Content | credential requests, urgency, prize lures, payment lures (English and Italian); HTML forms |
| Links | shown vs. real destination, raw IPs, shorteners, free hosting used for phishing pages, punycode, `user@host` tricks. Links are never opened |
| Attachments | executables and scripts, double extensions, content that doesn't match its extension, Office macros, HTML/SVG pages, archives containing executables, password-protected archives |

## Scoring

Each check emits *findings*, and each finding carries its own points and evidence. The
score is their sum, capped at 100:

| Level      | Score  |
|------------|--------|
| Clean      | 0–19   |
| Low        | 20–39  |
| Suspicious | 40–59  |
| High       | 60–79  |
| Critical   | 80–100 |

Some indicators force **Critical** whatever the score: an attachment flagged by several
VirusTotal engines, a malicious sandbox verdict, or a URL that is live in URLhaus.
Thresholds and per-signal weights can be changed in `config.yaml`.

## Privacy

- Uploading a file to VirusTotal or Hybrid Analysis makes it visible to other users of
  those services. Uploads are **off by default** (`sandbox_upload: never`); hash lookups
  are always private.
- Links in emails are never opened. URL checks are reputation lookups only.
- The AI summary gets the findings, the headers and a short redacted body excerpt. It
  never gets attachments.

## Development

```bash
pytest
ruff check . && ruff format --check .
```

## Credits

Built on a hackathon project by the original team:
[NobodyKnowNothing/phishing-email-detector](https://github.com/NobodyKnowNothing/phishing-email-detector).
