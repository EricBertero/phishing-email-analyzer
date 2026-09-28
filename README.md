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
- [x] **4. Threat intel**: URLhaus, Spamhaus DQS, AbuseIPDB, VirusTotal, optional rspamd
- [x] **5. Sandbox**: Hybrid Analysis detonation with async re-scoring
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

Analyse saved emails (`.eml`: in Gmail, use ⋮ → *Download message*):

```bash
phish scan-eml suspicious.eml            # score breakdown
phish scan-eml *.eml --verbose           # include passed checks
phish scan-eml suspicious.eml --json     # machine-readable
phish scan-eml suspicious.eml --offline  # no threat-intel lookups: nothing leaves the machine
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
| Threat intel | see below: link, domain, IP and attachment reputation; a real spam score |

## Threat intel

Every service is optional and free for personal use. Add the keys you have to `.env`
(see `.env.example`), then check them:

```bash
phish doctor
```

`doctor` queries each configured service with a known test indicator: the EICAR test file
on VirusTotal, and Spamhaus's permanent test listings.

| Service | What it checks | Free tier |
|---|---|---|
| [URLhaus](https://auth.abuse.ch/) | links and their hosts against known malware-distribution URLs. A **live** URL forces Critical | generous |
| [Spamhaus DQS](https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account/) | sending IP (ZEN) and sender/link domains (DBL) over DNS. A link domain listed for phishing or malware forces Critical, and so does a DBL-listed sender that also fails DMARC | non-commercial use |
| [AbuseIPDB](https://www.abuseipdb.com/account/api) | community abuse reports for the sending IP | 1,000/day |
| [VirusTotal](https://www.virustotal.com/gui/my-apikey) | attachment hashes first, then up to `vt_max_urls_per_email` links. An attachment or link flagged by `vt_malicious_threshold` engines forces Critical | 4/min, 500/day |
| [Hybrid Analysis](https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab) | existing sandbox reports for attachment hashes (a private lookup); also the sandbox itself, see below | free key |
| rspamd (self-hosted) | a real spam score from a full spam filter: Bayes, fuzzy hashes, RBLs | unlimited |

Results are cached in the database (`intel.cache_hours`), so restarts don't use up quota.
When a service is down or its quota is used up, the verdict is marked *partial*. Partial
verdicts are re-checked automatically (up to 3 times over the next two days), and the
label is updated if the verdict changes.

### Sandbox

An attachment that neither VirusTotal nor Hybrid Analysis has ever seen is the case a
hash lookup can't help with. Such files can be detonated in the Hybrid Analysis sandbox,
which reports a verdict (`malicious` forces **Critical**, `suspicious` adds points).

**Uploading a file makes it visible to other users of the service**, and attachments are
often private documents, so this is controlled by `sandbox_upload` in `config.yaml`:

| Setting | What happens to an unknown attachment |
|---|---|
| `never` (default) | nothing is uploaded; the email is scored on the static checks and lookups |
| `ask` | the file is queued and waits until you approve it |
| `always` | the file is uploaded automatically |

```bash
phish sandbox list          # jobs waiting for approval (or in progress)
phish sandbox approve 3     # or: approve --all
phish sandbox reject 4      # or: reject --all
```

What is never uploaded: files VirusTotal already knows (their verdict comes from
VirusTotal), images and plain text, files over `sandbox.max_file_mb`, files from local
`.eml` scans, and anything during `--dry-run`. Samples are sent with Hybrid Analysis's
"do not share with third parties" flag and without community access, unless you set
`sandbox.share_third_party: true`. The original file name is sent, since the analysis
depends on the extension.

The email is scored right away with what is known and labelled as usual. The sandbox
takes minutes; when it finishes, `phish run` re-scores the email and updates its Gmail
label, so a file that turns out to be malware moves the email to `Phish/Critical`.
Attachments are never stored: the worker fetches the message again from Gmail when it is
time to upload, and keeps the file in memory only.

Run `phish doctor` to check the key. This part of the client was written from the API
documentation and integrations that use it, and has not yet been run against a live key.

To get a real spam score, run rspamd in Docker and point the analyzer at it:

```bash
docker run -d --name rspamd -p 11333:11333 rspamd/rspamd
```

```yaml
# config.yaml
intel:
  rspamd_url: http://localhost:11333
```

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

Some indicators force **Critical** whatever the score: an attachment or link flagged by
several VirusTotal engines, a URL that is live in URLhaus, a link domain listed by Spamhaus
for phishing or malware, a DBL-listed sender that also fails DMARC, or a malicious
sandbox verdict.
Thresholds and per-signal weights can be changed in `config.yaml`.

## Privacy

- Uploading a file to VirusTotal or Hybrid Analysis makes it visible to other users of
  those services. Uploads are **off by default** (`sandbox_upload: never`); hash lookups
  are always private.
- Links in emails are never opened. URL checks are reputation lookups only.
- Threat-intel lookups send indicators only: URLs, domains, the sending IP and attachment
  hashes. They never get message text or attachments. Use `scan-eml --offline` to keep
  everything local.
- The one exception is the sandbox, which receives an attachment only if you allow it
  (`sandbox_upload`, default `never`). Message text is never sent. See [Sandbox](#sandbox).
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
