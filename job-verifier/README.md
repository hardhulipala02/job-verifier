# job-verifier — Job Scam Intelligence Network

A security tool that analyzes recruiter outreach and decides whether the sender
is likely reaching out with **malicious intent** — so you don't hand over
personal info or waste time on a scam.

It combines **deterministic checks** (cheap, run first) with an **optional LLM**
(run only when needed) and maps scam infrastructure into a **Neo4j graph** to
reveal coordinated syndicates.

## Three ways to use it

| For… | Use | What it analyzes |
|------|-----|------------------|
| An email in your inbox | **Web UI** (`/`) — paste raw email or upload `.eml` | Sender domain, SPF/DKIM/DMARC, impersonation, scam language |
| A LinkedIn / WhatsApp / platform message | **Chrome extension** — "Scan this page" | Scam language, links, Telegram/WhatsApp handles, impersonation cues |
| "I'd rather not paste anything" | **Forward-to-address email bot** — forward the email, get a report reply | Same as the email path, using the forwarded original's headers |

## Pipeline

```
parse ──► [auth gate] ──fail/misaligned──► persist
              │
              └─authenticated─► registry ─► behavior (LLM) ─► role ─► threat ─► dns ─► persist
```

Orchestrated with **LangGraph** (`main_graph.py`). SPF/DKIM/DMARC are validated
*before* any paid AI call: a hard authentication failure **or broken identifier
alignment** (the authenticated domain doesn't match the `From:` domain)
short-circuits straight to a `HIGH` verdict. The `threat` and `dns` nodes are
**async**, running URL reputation and DNS resolution concurrently.

## Modules

| File | Responsibility |
|------|----------------|
| `parser.py` | Robust `.eml` parsing, SPF/DKIM/DMARC extraction **+ identifier alignment**, entity extraction (domains, phones, Telegram/WhatsApp handles, URLs). |
| `registry.py` | Flags **impersonation**: free webmail (→ `MEDIUM`), **typosquatting** of known brands via Levenshtein distance, and **newly-registered domains** (< 60 days, via RDAP) (→ `HIGH`). |
| `llm_agent.py` | Deterministic scam-pattern detection + Gemini analysis with **exponential backoff/retries** and a **strict JSON schema**. |
| `role_check.py` | Extracts the advertised job title and (optionally) verifies it exists against public ATS job boards (**Greenhouse/Lever**). |
| `defang.py` | Rewrites URLs/domains into inert form (`hxxps[://]evil[.]com`) so reports are never clickable. |
| `threat_intel.py` | **Async** URL reputation via **VirusTotal/URLScan**; flags known-malicious links for quarantine (graceful without API keys). |
| `dns_intel.py` | **Async** A-record / NS-record resolution of sending domains for infrastructure mapping. |
| `graph_db.py` | Persists recruiters, entities, and resolved **IPs/nameservers** into **Neo4j**, linking shared attacker infrastructure. |
| `main_graph.py` | **LangGraph** stateful multi-agent orchestration; `analyze_email()` entrypoint. |
| `api.py` | Async **FastAPI** backend (`/health`, `/analyze`, `/analyze/upload`, `/analyze/message`) + serves the web UI. |
| `mailbot.py` | **Forward-to-address** bot: polls a mailbox over IMAP, analyzes forwarded emails, replies with a report over SMTP. |
| `report_format.py` | Renders a report into readable text/HTML for the email replies. |
| `schemas.py` | **Pydantic** models enforcing type-safe contracts everywhere. |
| `config.py` | Loads credentials from a git-ignored `.env`. |
| `static/` | The web UI (HTML/CSS/JS). |
| `extension/` | The Manifest V3 Chrome extension. |

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then fill in values (optional — see below)
```

### Configuration (all optional)

The pipeline runs fully with **deterministic checks only**. Add credentials to
`.env` to unlock more:

- `GOOGLE_API_KEY` — enables Gemini behavioral enrichment.
- `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` — enables graph persistence.
- `JOBVERIFIER_BOT_EMAIL` / `JOBVERIFIER_BOT_PASSWORD` — mailbox the forward-to-address bot watches and replies from (Gmail: use an [App Password](https://myaccount.google.com/apppasswords)). Optional host overrides: `JOBVERIFIER_IMAP_HOST` (default `imap.gmail.com`), `JOBVERIFIER_SMTP_HOST` (default `smtp.gmail.com`).
- `JOBVERIFIER_VERIFY_ROLE=1` — turns on best-effort **role verification**: checks whether the advertised title exists on the claimed company's public job board (Greenhouse/Lever). Off by default so tests stay offline. A real role on a real board does **not** clear an otherwise scammy message — scammers often borrow real titles.

When a credential is absent, that stage is skipped gracefully (the LLM falls
back to deterministic-only; persistence becomes a no-op). Secrets live only in
`.env`, which is excluded from git via `.gitignore`.

## Usage

### CLI

```bash
python main_graph.py sample_emails/telegram_scam.eml
```

### Library

```python
from main_graph import analyze_email

report = analyze_email("path/to/email.eml")   # or raw string / bytes
print(report.model_dump_json(indent=2))
```

### Web UI

```bash
uvicorn api:app --reload
# then open http://127.0.0.1:8000/
```

Paste a raw email (or upload a `.eml`) on the **Email** tab, or paste a recruiter
message on the **LinkedIn / Message** tab, and get a color-coded report.

### API

```bash
uvicorn api:app --reload
# POST /analyze            {"raw_email": "...", "use_llm": false}
# POST /analyze/upload     multipart file=<your.eml>
# POST /analyze/message    {"text": "...", "sender_name": "Anne"}
# GET  /health
```

### Chrome extension

1. Start the API (`uvicorn api:app --reload`) so the extension has a backend.
2. Open `chrome://extensions`, enable **Developer mode**, click **Load
   unpacked**, and select the `extension/` folder.
3. Open a LinkedIn (or any) conversation, click the extension, and hit
   **Scan this page** (or select the message text first). The API base defaults
   to `http://127.0.0.1:8000` and is editable in the popup.

### Forward-to-address email bot

Set `JOBVERIFIER_BOT_EMAIL` / `JOBVERIFIER_BOT_PASSWORD`, then run:

```bash
python mailbot.py
```

Forward any suspicious recruiter email to that address; the bot replies with a
report. It prefers the attached original message (so SPF/DKIM/DMARC still work)
and falls back to the forwarded body text.

## Example output

```json
{
  "sender": "anne.hr2024@gmail.com",
  "security": {"dmarc": "pass", "spf": "pass", "dkim": "pass"},
  "entities": {"telegram_handles": ["globexhr"], "domains": ["gmail.com"]},
  "impersonation": {"claimed_company": "Globex Corporation", "is_impersonation": true},
  "verdict": {
    "risk_level": "HIGH",
    "flags_detected": [
      "Forced migration to an external chat app",
      "Promise of an upfront check / payment before work",
      "Corporate impersonation"
    ]
  }
}
```

## Graph queries

After persisting reports, find coordinated syndicates that reuse infrastructure:

```cypher
MATCH (r1:Recruiter)-[:USES_TELEGRAM]->(t)<-[:USES_TELEGRAM]-(r2:Recruiter)
WHERE r1 <> r2
RETURN r1, t, r2
```

## Tests

```bash
pytest
```

All external services (Gemini, Neo4j, DNS) are mocked, so the suite runs offline
without any credentials.
