# Job Scam Intelligence Network — Technical Overview

A security tool that detects malicious recruiter outreach (job scams) across
three user-facing surfaces, combining **deterministic checks**, an **optional
LLM**, **threat intelligence**, and a **Neo4j graph** that maps coordinated scam
syndicates by their shared infrastructure.

The design principle throughout: **deterministic-first, AI-last, fail-safe**.
Cheap, reliable signals run first and can decide a verdict on their own; the
expensive LLM only runs when it adds value; every external dependency (LLM,
Neo4j, VirusTotal/URLScan, RDAP, DNS, ATS APIs) is optional and degrades
gracefully so the pipeline always produces a verdict.

---

## 1. Two ways to use it

| Surface | Entry point | What it analyzes |
| --- | --- | --- |
| **Chrome extension** | `extension/` (Load unpacked) | Scrapes the visible recruiter message on a page (LinkedIn, etc.) and reports in the popup. |
| **Forward-to-address bot** | `mailbot.py` watching a mailbox | User forwards a suspicious email; bot replies with a report to the forwarder. |

The two call the same engine (`analyze_email` for raw emails, `analyze_message`
for header-less platform text), so detection logic is identical everywhere.

---

## 2. Pipeline architecture (LangGraph)

Orchestrated as a stateful multi-agent graph in `main_graph.py`:

```
parse ──► [auth gate] ──gateway_failed──► spoofed ──► persist
              │
              └── ok ──► registry ──► behavior(LLM) ──► role ──► threat ──► dns ──► persist
```

- **parse** (`parser_node`) — parse the `.eml`, extract body text, security
  headers, entities, and build the email **reference** (see §6).
- **auth gate** (`route_security`) — deterministic short-circuit. If
  authentication hard-fails **or** identifier alignment is broken, route to
  `spoofed` and emit a HIGH verdict **without ever calling the LLM**.
- **registry** (`registry_node`) — impersonation / typosquatting / domain-age.
- **behavior** (`behavior_node`) — scam-language analysis (deterministic rules,
  optionally enriched by Gemini), then sender-trust escalation.
- **role** (`role_node`) — best-effort role existence + open-roles mapping.
- **threat** (`threat_node`, async) — defang URLs + optional VirusTotal/URLScan.
- **dns** (`dns_node`, async) — A/NS resolution for infrastructure mapping.
- **persist** (`persist_node`) — write the report + entities + infra to Neo4j.

State is a `TypedDict` (`AgentState`); each node returns a partial state dict
that LangGraph merges. The graph is compiled once at import (`app = build_app()`).
Async nodes run under `asyncio.run(app.ainvoke(...))` for sync callers, and
inside FastAPI's threadpool for the async API.

---

## 3. Modules

| File | Responsibility |
| --- | --- |
| `parser.py` | Robust `.eml`/bytes/string parsing; plain-text body extraction from nested MIME; SPF/DKIM/DMARC reading **and identifier-alignment**; entity extraction (domains, phones, Telegram/WhatsApp, URLs); `build_reference()`. |
| `registry.py` | Impersonation detection (claimed company vs. sending domain), free-webmail detection, **Levenshtein typosquatting** vs. known brands + claimed company, **RDAP domain-age** lookup. |
| `llm_agent.py` | Deterministic scam-pattern rules (forced chat-app migration, fake check/payment, hire-without-interview, urgency, etc.) + optional **Gemini** call with **strict Pydantic JSON** output and **exponential-backoff retries** (`tenacity`). |
| `role_check.py` | Extracts advertised title; queries **Greenhouse/Lever public ATS APIs**; returns the company's live openings, flags matches, treats "no roles" as inconclusive. |
| `threat_intel.py` | **Async** URL reputation via VirusTotal/URLScan; always defangs; graceful without keys. |
| `dns_intel.py` | **Async** A-record / NS-record resolution (`dnspython`) for infra mapping. |
| `defang.py` | Rewrites URLs/domains to inert form (`hxxps[://]evil[.]com`) so reports are never clickable. |
| `graph_db.py` | Neo4j persistence of recruiters, analyses, entities, and resolved IPs/nameservers; links shared infrastructure. |
| `main_graph.py` | LangGraph orchestration; `analyze_email()` / `analyze_message()` entrypoints. |
| `schemas.py` | Strict Pydantic models shared across pipeline, API, and DB. |
| `config.py` | Centralized env/`.env` config; per-service enable flags. |
| `api.py` | Async **FastAPI** backend + serves the web UI. |
| `mailbot.py` | IMAP/SMTP forward-to-address bot. |
| `report_format.py` | Renders a `ScamReport` to plain-text + HTML for email/UI. |

---

## 4. Detection signals

### 4.1 Authentication & alignment (deterministic gate)
- Parses the gateway-injected `Authentication-Results` header for SPF/DKIM/DMARC.
- **Identifier alignment**: the authenticated domain (`smtp.mailfrom`, DKIM
  `d=`/`i=`) must match the `From:` registrable domain. A pass that is
  *misaligned* (e.g. SPF passes for `bulk-mailer.ru` while the mail claims to be
  from `google.com`) is treated as a gateway failure → **HIGH, no LLM**.
- A hard SPF/DKIM/DMARC `fail` is likewise an immediate HIGH short-circuit.

### 4.2 Impersonation, typosquatting & domain age (`registry.py`)
- Claimed-company vs. sending-domain mismatch and free-webmail detection.
- **Typosquatting**: Levenshtein edit distance of the registrable sending domain
  against 20+ known brand domains plus the claimed company; near-misses (e.g.
  `linkedln.com` vs `linkedin.com`, distance 1) → HIGH.
- **Domain age**: free RDAP lookup; registration **< 60 days** → HIGH risk spike.

### 4.3 Behavioral / linguistic (`llm_agent.py`)
- Deterministic detectors for the classic recruiter-scam playbook: forced
  migration to Telegram/WhatsApp, fake check/upfront payment, buy-equipment,
  hire-without-interview, urgency/pressure, corporate impersonation cues.
- Optional Gemini enrichment with a strict response schema and retries; the
  verdict is the **max risk** of deterministic and LLM results.
- **Sender-trust escalation**: outright impersonation → HIGH; recruiter using a
  free webmail address → at least MEDIUM.

### 4.4 Role existence & open-roles mapping (`role_check.py`)
- Extracts the advertised title from the message.
- Queries **Greenhouse** (`boards-api.greenhouse.io`) and **Lever**
  (`api.lever.co`) public JSON APIs (no key) by deriving plausible board slugs.
- Returns the company's **actual live openings** (title + URL), flagging the ones
  that match the claimed role.
- **No live roles is inconclusive, not a red flag** — the report says so and
  links a direct LinkedIn Jobs search to verify. A real role does **not** clear
  an otherwise scammy message (scammers borrow real titles).

### 4.5 URL reputation & defanging (`threat_intel.py`)
- Every URL is defanged before it appears in any report/reply.
- Async VirusTotal + URLScan lookups run concurrently; a known-malicious link
  forces HIGH and is flagged "quarantined". Without API keys the node still runs
  and reports "reputation check skipped".

### 4.6 DNS infrastructure mapping (`dns_intel.py`)
- Async A-record + NS-record resolution of sending/extracted domains.
- Stored in Neo4j so distinct recruiters sharing an IP or nameserver link up,
  exposing shared attacker infrastructure.

---

## 5. Neo4j graph model

Each analyzed message persists this subgraph (`graph_db.py`):

```
(Recruiter {address, risk, summary, analysis_id, subject, last_seen})
   ├─[:ANALYZED_AS]──►(Analysis {analysis_id, subject, risk, from_address, analyzed_at})
   ├─[:USES_DOMAIN]──►(Domain {name})
   │                      ├─[:RESOLVES_TO]──►(IPAddress {address})
   │                      └─[:USES_NAMESERVER]──►(NameServer {host})
   ├─[:USES_PHONE]─────►(PhoneNumber {number})
   ├─[:USES_TELEGRAM]──►(TelegramHandle {handle})
   ├─[:USES_WHATSAPP]──►(WhatsAppNumber {number})
   └─[:LINKS_TO]───────►(Url {value})
```

Because entities are `MERGE`d on their natural key, two separate scam reports
that reuse the same Telegram handle, phone, IP, or nameserver automatically
connect — that is the "syndicate map". Example query:

```cypher
// Recruiters that share a Telegram handle
MATCH (r1:Recruiter)-[:USES_TELEGRAM]->(t)<-[:USES_TELEGRAM]-(r2:Recruiter)
WHERE r1 <> r2
RETURN r1.address, t.handle, r2.address;

// Domains sharing a nameserver (shared infrastructure)
MATCH (d1:Domain)-[:USES_NAMESERVER]->(n)<-[:USES_NAMESERVER]-(d2:Domain)
WHERE d1 <> d2
RETURN n.host, collect(DISTINCT d1.name);
```

**Local setup** (Docker):

```bash
docker run -d --name jobverifier-neo4j --restart unless-stopped \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/<password> neo4j:5.26
```

Then in `.env`: `NEO4J_URI=bolt://localhost:7687`, `NEO4J_USER=neo4j`,
`NEO4J_PASSWORD=<password>`. Browse at `http://localhost:7474`. Persistence is a
no-op when these are unset.

---

## 6. Email reference / traceability

Every report carries an `EmailReference` (`schemas.py`) so a user can map a
verdict back to the exact message it came from:

- `analysis_id` — stable, human-readable handle, e.g. `JSC-8C4E4B3C7D`, derived
  from the message identity (`Message-ID`, else `from+subject+date` hash) so the
  same email always yields the same id.
- `from_address`, `subject`, `date`, `message_id`.

It is shown at the top of every text/HTML report ("Analyzed email" block) and in
the web UI, and persisted on both the `Recruiter` and `Analysis` nodes.

---

## 7. Schemas (type-safe contracts)

Strict Pydantic models flow end-to-end (LLM → pipeline → API → DB):
`RiskLevel`, `AuthStatus`, `SecurityHeaders` (with `aligned`/`gateway_failed`),
`ExtractedEntities`, `ImpersonationCheck` (typosquat + age fields), `URLVerdict`,
`ThreatIntel`, `DomainDNS`, `OpenRole`, `RoleCheck` (with `open_roles`,
`board_found`), `BehavioralVerdict`, `EmailReference`, and the aggregate
`ScamReport`.

---

## 8. API

Async FastAPI (`api.py`), also serves the web UI:

- `GET /health` → `{status, llm_enabled, neo4j_enabled}`
- `POST /analyze` → `{raw_email, persist?, use_llm?}`
- `POST /analyze/upload` → multipart `.eml` file
- `POST /analyze/message` → `{text, sender_name?, platform?, persist?, use_llm?}`

All return a full `ScamReport` JSON.

---

## 9. Configuration (all optional)

In a git-ignored `.env`:

| Var | Effect |
| --- | --- |
| `GOOGLE_API_KEY`, `GEMINI_MODEL` | Enable Gemini behavioral enrichment. |
| `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` | Enable graph persistence. |
| `JOBVERIFIER_BOT_EMAIL` / `JOBVERIFIER_BOT_PASSWORD` | Mailbox for the bot (Gmail App Password). |
| `JOBVERIFIER_IMAP_HOST` / `_SMTP_HOST` / ports | Provider overrides. |
| `JOBVERIFIER_VERIFY_ROLE=1` | Turn on ATS role verification. |
| `JOBVERIFIER_RESOLVE_DNS=1` | Turn on async DNS infra mapping. |
| `VIRUSTOTAL_API_KEY` / `URLSCAN_API_KEY` | Activate live URL reputation. |
| `*_TIMEOUT`, `LLM_MAX_RETRIES`, `LLM_BACKOFF_BASE_SECONDS` | Tuning. |

---

## 10. Tests

`pytest` — **72 tests, fully offline** (all network/LLM/Neo4j mocked via
`conftest.py`), `ruff`-clean. Coverage spans parsing, auth alignment, entity
extraction, impersonation/typosquatting, RDAP, role verification + open-roles,
defang, threat-intel, DNS, the LangGraph nodes, the API, and the mailbot.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
```

---

## 11. Design principles recap

1. **Deterministic-first / AI-last** — cheap reliable checks gate expensive ones.
2. **Fail-safe degradation** — every external service is optional.
3. **Strict typed contracts** — Pydantic everywhere, no untyped dict-passing.
4. **Modular separation** — parsing / reasoning / DB / orchestration are distinct.
5. **Safety in reporting** — URLs defanged; secrets only in git-ignored `.env`.
6. **Traceability** — every verdict carries a stable reference to its source email.
