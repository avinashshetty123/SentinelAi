# Architecture

## Overview

```
┌──────────────────────────┐   HTTPS JSON (/api/v1)    ┌─────────────────────────────────────────┐
│ Next.js 16 (App Router)  │ ────────────────────────▶ │ FastAPI (single Uvicorn worker)         │
│ React 19 · TanStack Query│                           │  core/  config, auth, rate limit,       │
│ RHF + Zod · Recharts     │ ◀──────────────────────── │         middleware, error envelope      │
│ (Vercel)                 │   WebSocket /ws/events    │  api/v1 routers                         │
└──────────────────────────┘                           │  services/                              │
                                                       │   detection/ rules · URL · classifier   │
                                                       │   scoring/   explainable engine         │
                                                       │   llm/       Groq service (server only) │──▶ Groq API
                                                       │   events/    persist → broadcast        │
                                                       │   incidents, demo, retention, audit     │
                                                       │  websocket/  in-process hub             │
                                                       └───────────────┬─────────────────────────┘
                                                                       │ SQLAlchemy 2 async (asyncpg)
                                                                       ▼
                                                               PostgreSQL (Alembic)
```

The frontend contains no business logic. It renders what the API returns and calls the API for every action. The Groq key exists only in the backend's environment.

## Detection pipeline (message)

`POST /api/v1/scans/message` runs `app/services/analysis.py::analyze_message`:

1. **Validate.** Pydantic checks length (≤ 10 000 characters), a non-blank body and the content type. The request body is capped at 64 KiB.
2. **Normalize** (`detection/text.py`). Invisible and bidi-control characters are counted and removed. Mixed-script words such as a Cyrillic `а` inside `pаypal` are recorded, and their lookalike letters are folded to Latin. The text is NFKC-normalized and whitespace collapsed.
3. **Extract features.** URLs are extracted (explicit, `www.`, bare domains with common or abused TLDs, and defanged `hxxp`). The content type is auto-detected when set to `auto`.
4. **Deterministic rules** (`detection/message_rules.py`). There are 20 indicators. Each fires at most once and keeps its first evidence excerpt and match count. Rules that ask for secrets have a *negation guard*, so "never share your OTP" does not fire.
5. **URL checks.** Each extracted URL goes through the offline URL analyzer. Its findings are re-categorized as `url` evidence for the message.
6. **Combination rules.** Examples: credential request + urgency, credential request + link, reward or job + fee (advance-fee), and remote access + support pretext.
7. **Classifier.** A TF-IDF + logistic-regression baseline produces a spam-class probability, which is mapped to 0–12 points.
8. **Optional LLM.** This step runs only when `use_llm=true` and Groq is configured. Text is minimized first: long digit runs become `[NUMBER]` and e-mail addresses become `[EMAIL]`, and the text is truncated to `GROQ_MAX_INPUT_CHARS`.
9. **Validate the LLM output.** Strict JSON Schema plus Pydantic `extra="forbid"`. Each signal's `evidence` must be a normalized substring of the text that was sent; otherwise it is **discarded**. A signal in a category already covered by a rule only *corroborates* it (0 points). An uncorroborated signal adds 5 points, with the LLM category capped at 10. LLM recommendations that contain links or phone numbers are dropped.
10. **Score** (`scoring/engine.py`), described below.
11. **Explain.** A template summary and recommendations are always generated. The AI summary, when present, is shown separately and labelled.
12. **Persist metadata.** The scan row and finding rows are stored. Raw text is never stored.
13. **Publish.** If the level is at or above `EVENT_MIN_LEVEL` (default HIGH), a `high_risk_message` event is persisted. If it is at or above `AUTO_INCIDENT_MIN_LEVEL` (default CRITICAL), an incident is opened and linked. After commit, events are broadcast over WebSocket.

URL scans (`POST /scans/url`) use the same steps with the URL analyzer as the only detector. For URLs the LLM only *explains*: it receives the URL without its query string plus the extracted features, and it never adds points.

## Risk scoring

```
for each category c:
    weights = sorted(weights of unique findings in c, descending)
    raw_c   = w1 + 0.5·w2 + 0.5·w3 + …
    pts_c   = min(raw_c, cap_c)
score = clamp(round(Σ pts_c), 0, 100)
```

- **Dedup:** one finding per `rule_id`. Repeated keywords increase `match_count`, not points.
- **Thresholds** are configurable: LOW < 25 ≤ MEDIUM < 50 ≤ HIGH < 75 ≤ CRITICAL.
- **Evidence strength** is based on deterministic categories only:
  - `none`: score 0.
  - `limited`: one category.
  - `moderate`: two or more categories, or any high-severity finding.
  - `strong`: four or more categories, or two or more categories including a high-severity finding.
- **Missing data:** a missing classifier or LLM never lowers a score. Unknown reputation is reported as `not_configured`.
- **Reproducibility:** for the same input, `RULE_VERSION`, `URL_RULE_VERSION`, `SCORING_VERSION` and the classifier artifact always produce the same deterministic score. The LLM can only add bounded points, and only from grounded signals.

**Category caps:**

| Category | Cap | Category | Cap |
|---|---|---|---|
| credential_request | 40 | url (in messages) | 35 |
| payment_request | 30 | classifier | 12 |
| urgency | 25 | llm | 10 |
| impersonation | 15 | combination | 30 |
| reward_lure | 25 | transport (URL) | 10 |
| job_scam | 20 | deception (URL) | 40 |
| secrecy | 15 | host (URL) | 30 |
| verification_bypass | 20 | brand (URL) | 40 |
| remote_access | 30 | redirection (URL) | 15 |
| download_install | 25 | content (URL) | 25 |
| personal_info | 25 | prompt_injection | 20 |
| obfuscation | 15 | | |

### Message indicators (`msg-rules-1.0`)

| Rule | Category | Weight |
|---|---|---|
| `MSG_URGENCY_PRESSURE` Time pressure | urgency | 10 |
| `MSG_URGENCY_THREAT` Threat of loss or penalty | urgency | 14 |
| `MSG_CREDENTIAL_OTP` Request for a one-time code | credential_request | 30 |
| `MSG_CREDENTIAL_SECRET` Passwords, PINs or card data | credential_request | 28 |
| `MSG_CREDENTIAL_VERIFY` Account verification request | credential_request | 16 |
| `MSG_PAYMENT_FEE` Fee or money transfer | payment_request | 18 |
| `MSG_PAYMENT_UNUSUAL` Gift cards, crypto, wire services | payment_request | 20 |
| `MSG_PAYMENT_COLLECT` Approve-to-receive trick | payment_request | 14 |
| `MSG_IMPERSONATION_AUTHORITY` Government/police/tax claims | impersonation | 8 |
| `MSG_IMPERSONATION_BRAND` Brand support team / generic greeting | impersonation | 8 |
| `MSG_REWARD_LURE` Prize, lottery, refund lure | reward_lure | 18 |
| `MSG_UNREALISTIC_RETURN` Guaranteed or high returns | reward_lure | 18 |
| `MSG_JOB_SCAM` Too-easy job pattern | job_scam | 14 |
| `MSG_SECRECY` Keep it secret | secrecy | 14 |
| `MSG_VERIFICATION_BYPASS` Avoid official channels | verification_bypass | 16 |
| `MSG_REMOTE_ACCESS` AnyDesk/TeamViewer/screen share | remote_access | 24 |
| `MSG_DOWNLOAD_INSTALL` Install app / open file | download_install | 18 |
| `MSG_PERSONAL_INFO` Identity documents / personal data | personal_info | 16 |
| `MSG_PROMPT_INJECTION` Instructions aimed at AI filters | prompt_injection | 20 |
| `MSG_OBFUSCATION` Invisible chars / mixed scripts | obfuscation | 12 |

**Combination rules:**

| Rule | Weight |
|---|---|
| `COMBO_CREDENTIAL_URGENCY` | 12 |
| `COMBO_LINK_CREDENTIAL` | 12, or 8 if no URL finding weighs ≥ 10 |
| `COMBO_PAYMENT_URGENCY` | 8 |
| `COMBO_IMPERSONATION_REQUEST` | 10 |
| `COMBO_ADVANCE_FEE` | 14 |
| `COMBO_REMOTE_ACCESS_SUPPORT` | 12 |

### URL checks (`url-rules-1.0`)

| Rule | Category | Weight |
|---|---|---|
| `URL_USERINFO` text before `@` | deception | 30 |
| `URL_OBFUSCATED_IP` decimal/hex/octal IP | deception | 30 |
| `URL_MIXED_SCRIPT` homograph label | deception | 30 |
| `URL_PUNYCODE` IDN domain | deception | 15 |
| `URL_ENCODED_HOST` percent-encoded host | deception | 15 |
| `URL_ENCODING_ANOMALY` double/encoded separators | deception | 12 |
| `URL_IP_HOST` raw IP | host | 22 |
| `URL_INTERNAL_HOST` private/loopback/link-local/metadata | host | 15 |
| `URL_NONSTANDARD_PORT` | host | 12 |
| `URL_SUBDOMAIN_DEPTH` ≥ 3 subdomain levels | host | 10 |
| `URL_ABUSED_TLD` | host | 8 |
| `URL_NO_PUBLIC_SUFFIX` | host | 6 |
| `URL_LOOKALIKE` homoglyph/typo of a known brand | brand | 35 |
| `URL_BRAND_IN_SUBDOMAIN` | brand | 28 |
| `URL_BRAND_IN_DOMAIN` brand token in unrelated domain | brand | 18 |
| `URL_SHORTENER` | redirection | 10 |
| `URL_EMBEDDED_URL` open-redirect shape | redirection | 10 |
| `URL_EXECUTABLE` .apk/.exe/… | content | 18 |
| `URL_SENSITIVE_KEYWORDS` login/verify/kyc… | content | 8 |
| `URL_LONG` > 200 characters | content | 5 |
| `URL_NO_TLS` http:// | transport | 8 |
| `URL_COMBO_BRAND_CREDENTIAL` | combination | 12 |
| `URL_COMBO_INSECURE_LOGIN` | combination | 10 |
| `URL_COMBO_IP_CREDENTIAL` | combination | 10 |
| `URL_OFFICIAL_DOMAIN`, `URL_RESERVED_TLD` | info | 0 |

HTTP alone, a shortener alone or deep subdomains alone stay LOW by design.

## Groq integration

`app/services/llm/groq_service.py`:

- **SDK and model.** It uses the official `groq` SDK (`AsyncGroq`). The model comes from `GROQ_MODEL`, default `openai/gpt-oss-20b`. That is a Groq production model listed as supporting strict `json_schema` structured outputs.
- **Request parameters.** `response_format={"type":"json_schema","json_schema":{…,"strict":true}}`, `reasoning_effort` (default low), `include_reasoning=false`, `temperature=0.2` and a bounded `max_completion_tokens`.
- **Fallback format.** If Groq returns `json_validate_failed`, which was observed intermittently, the service retries once in `json_object` mode with the schema stated in the prompt. The result is still Pydantic-validated.
- **Time limits.** Per-request timeout `GROQ_TIMEOUT_SECONDS` and SDK retries `GROQ_MAX_RETRIES` for transient errors, under an overall `asyncio.wait_for` deadline.
- **Request budget.** A global per-minute budget (`GROQ_REQUESTS_PER_MINUTE`) is enforced before any network call.
- **Errors.** Errors are classified as `timeout`, `rate_limited`, `auth_error`, `provider_error`, `invalid_output`, `not_configured`, `disabled` or `skipped`. Every one of them degrades to the deterministic result, and the UI shows which status applied.
- **Logging.** Logs contain only operation, status, latency, model and the provider's error code. Prompts, responses and user content are never logged.

**Prompt-injection defense in depth:**
1. The system prompt declares the content untrusted and forbids following it.
2. Content is wrapped in an unguessable random boundary (`<<<UNTRUSTED_{random}>>>`).
3. The model has no tools, and no secrets reach the prompt.
4. Output is validated against a strict schema, so extra fields are rejected.
5. Evidence quotes are verified against the submitted text.
6. The LLM cannot lower the score and can add at most 10 points.
7. A deterministic `MSG_PROMPT_INJECTION` rule flags injection attempts independently.

## WebSocket flow

```
action (scan / demo / incident change)
  → EventCreate (Pydantic) → INSERT security_events → COMMIT
  → manager.broadcast({"type": "event.created", "data": EventOut})
  → browser EventStreamProvider → invalidate TanStack queries (debounced 400 ms) → UI updates
```

- **Message types:** `hello`, `ping`, `event.created`, `event.updated`, `scan.created`, `incident.created`, `incident.updated`, `demo.progress`, `demo.reset` and `simulator.status`.
- **Origin check:** browsers don't apply CORS to WebSockets, so the server validates `Origin` against `CORS_ORIGINS`/`CORS_ORIGIN_REGEX`.
- **Token mode:** the first client frame must be `{"type":"auth","token":…}`, so the token never appears in URLs or logs. Closing code 4401 means unauthorized.
- **Resilience:** the client reconnects with exponential backoff and jitter, and catches up by invalidating queries on `hello`. While disconnected it polls every 15 s.
- **Limits:** the hub keeps at most 200 clients, a 2 s send timeout, a 100-message in-memory history and 25 s pings. The DB event history is pruned to `EVENT_HISTORY_MAX`, keeping events linked to incidents.

## Demo system

- **Scenarios** live in `services/demo/scenarios.py` and use only synthetic text, RFC 2606 `.example` domains and RFC 5737 `203.0.113.0/24` addresses.
- **Runner:** `services/demo/runner.py` executes each step through `analyze_message`, `analyze_url_scan`, `create_event`, `create_incident` and `add_note`. Every row is tagged `source=demo` and `demo_run_id`. Only one run executes at a time; a second request gets HTTP 409.
- **Simulator:** a single-instance background generator of `source=simulation` events. It stops itself after `DEMO_SIMULATOR_MAX_SECONDS`.
- **Reset:** deletes only rows with `source in (demo, simulation)`, plus audit records of demo incidents and the demo runs, and records a `demo.reset` audit entry. `tests/test_demo.py` verifies this.

## Deployment shape

The backend runs as one Docker container: migrations run on start, then one Uvicorn worker serves requests. The in-process hub, rate limiter and demo runner all assume a single instance. To scale out, put Redis behind `ConnectionManager.broadcast` and the rate limiter, and move the demo runner to a worker.
