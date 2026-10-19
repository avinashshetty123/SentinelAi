# SentinelAI

**Explainable scam, URL and security-event analysis.** It's built for the hackathon track *AI for Cybersecurity & Digital Safety*.

SentinelAI analyzes suspicious messages and links, explains *why* they look dangerous, scores the risk with a transparent engine, and turns high-risk detections into live security events and incidents.

```
Analyze → Detect → Explain → Score risk → Recommend action → Create incident → Monitor events
```

It is not a chatbot that guesses "scam / not scam". The risk score comes from **deterministic security rules**, **offline URL heuristics** and a **measured ML baseline**. A **Groq-hosted LLM** explains the evidence. Its output is schema-validated and quote-checked, and it can never set the score on its own.

---

## Features

| Area | What it does |
|---|---|
| Message analyzer | It runs 20 documented indicators: credential/OTP requests, payment pressure, impersonation, reward lures, job scams, secrecy, verification bypass, remote access, downloads, personal-data requests, prompt injection and hidden characters. Combination rules add points when indicators co-occur. |
| URL analyzer | It analyzes links **offline**, without visiting them. Checks cover user-info tricks, raw/obfuscated/internal IPs, punycode and mixed-script homographs, lookalike/typosquat domains, brand-in-subdomain, encoding anomalies, unusual ports, shorteners, embedded redirects, executable downloads and abused TLDs. |
| Risk engine | Each rule contributes once. Inside a category, the strongest rule counts fully, the rest count at 50%, and the category is capped. The total is clamped to 0–100, and rule and scoring versions are recorded. |
| ML baseline | TF-IDF + logistic regression trained on the UCI SMS Spam Collection (CC BY 4.0). Held-out F1 is 0.94 and the false-positive rate is 0.9% ([details](docs/ML_EVALUATION.md)). Its contribution is capped at 12 points. |
| Groq LLM | The model gives a plain-language explanation, social-engineering signals and recommendations. It uses strict JSON-schema structured output plus Pydantic validation. Any signal whose quote is not found in the submitted text is discarded. A deterministic fallback always exists. |
| Real-time dashboard | Shows metrics from stored data, activity charts, risk distribution, a live WebSocket event stream, provider status and polling fallback. |
| Incidents | Create, investigate, annotate, resolve or mark false positive. Includes linked events, a timeline, an audit trail and an optional Groq incident summary. |
| Safe attack replay | Three synthetic scenarios run through the **real** pipeline, then events stream in and an incident opens. A demo-only reset never touches application data. |
| Privacy | Raw message text is never stored. Text is minimized before it goes to the LLM. URL paths are not stored. Retention purge runs automatically, and logs never contain user content. |

## Architecture

```
Next.js 16 (Vercel) ──HTTPS/JSON──▶ FastAPI (Render, Docker) ──▶ PostgreSQL
        ▲                                   │  ├─ detection: rules, URL analyzer, classifier
        └────────── WebSocket ◀─────────────┘  ├─ scoring engine
                                               ├─ Groq service (server-side only) ──▶ Groq API
                                               └─ events → persist → broadcast
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## Repository layout

```
backend/    FastAPI app (app/), Alembic migrations, ML training + artifact (ml/), pytest suite (tests/)
frontend/   Next.js App Router UI, Vitest unit tests (tests/), Playwright E2E (e2e/)
docs/       Architecture, API, data model, threat model, privacy, ML evaluation, deployment, demo script
docker-compose.yml   Local full stack (Postgres + API + UI)
render.yaml          Render blueprint (API + Postgres)
```

## Prerequisites

- Docker Desktop. This is the simplest path.
- Or, for running the services natively: Python 3.12, Node.js ≥ 22.12 with npm 11, and PostgreSQL 15+.
- Optionally, a Groq API key from https://console.groq.com. Everything works without it.

## Quick start (Docker)

```bash
# 1. Configure the backend. backend/.env is git-ignored.
cp backend/.env.example backend/.env       # then set GROQ_API_KEY (optional)

# 2. Start everything
docker compose up --build

# 3. Open
#   UI:        http://localhost:3000
#   API docs:  http://localhost:8000/docs
#   Health:    http://localhost:8000/health
```

Migrations run automatically when the backend container starts.

To load clearly labelled demo data, either run the scenarios from **Attack replay** or use the seed script:

```bash
docker compose exec backend python -m scripts.seed
```

## Running without Docker

```bash
# Database
docker run -d --name sentinel-pg -e POSTGRES_USER=sentinel -e POSTGRES_PASSWORD=sentinel \
  -e POSTGRES_DB=sentinel -p 5432:5432 postgres:17-alpine

# Backend
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# Frontend (new terminal)
cd frontend
cp .env.example .env.local
npm install
npm run dev
```

## Environment variables

**Backend.** `backend/.env.example` documents every variable. The key ones:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL URL. `postgres://` and `postgresql://` are normalized to asyncpg, and `sslmode=` becomes `ssl=`. |
| `GROQ_API_KEY`, `GROQ_MODEL`, `GROQ_ENABLED` | LLM provider (server-side only). The default model is `openai/gpt-oss-20b`. |
| `CORS_ORIGINS`, `CORS_ORIGIN_REGEX` | Allowed browser origins. These also gate WebSocket `Origin`. |
| `AUTH_MODE` | `open` (dev/demo) or `token`, which requires `ADMIN_API_TOKEN` of 24+ characters. Production refuses `open` unless `ALLOW_OPEN_MODE_IN_PRODUCTION=true`. |
| `STORE_FINDING_EXCERPTS`, `STORE_AI_SUMMARIES`, `SCAN_RETENTION_DAYS` | Privacy controls. Excerpts and AI summaries are off by default; scans are kept 30 days. |
| `RISK_THRESHOLD_*`, `EVENT_MIN_LEVEL`, `AUTO_INCIDENT_MIN_LEVEL` | Scoring and event policy. |

**Frontend.** These are public; never put secrets in them.

| Variable | Purpose |
|---|---|
| `NEXT_PUBLIC_API_URL` | Base URL including `/api/v1`. |
| `NEXT_PUBLIC_WS_URL` | Optional override for the WebSocket URL. |

## Testing

```bash
# Backend: lint, types, tests (SQLite by default; set TEST_DATABASE_URL to use PostgreSQL)
cd backend
ruff check app ml tests && mypy app && pytest -q
alembic upgrade head && alembic check          # migrations match models

# Frontend
cd frontend
npm run lint && npm run typecheck && npm test && npm run build

# End-to-end (requires the stack running, e.g. docker compose up)
npx playwright install chromium
npx playwright test
```

Latest local results are listed in [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md#test-results).

## Deployment

- **Backend + database on Render:** use `render.yaml` (Blueprint).
- **Frontend on Vercel:** set the root directory to `frontend` and set `NEXT_PUBLIC_API_URL`.

Step-by-step instructions are in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Troubleshooting

| Symptom | Fix |
|---|---|
| UI says "Cannot reach the SentinelAI API" | Check that the backend is running and that `NEXT_PUBLIC_API_URL` is correct (it is baked in at build time). Also check that `CORS_ORIGINS` includes the UI origin. |
| Event stream shows "Reconnecting/Offline" | The WebSocket origin must be in `CORS_ORIGINS`/`CORS_ORIGIN_REGEX`. Behind a proxy, use `wss://`. The UI falls back to polling every 15 s. |
| "Token required" banner | The backend runs with `AUTH_MODE=token`. Paste `ADMIN_API_TOKEN` on the **Settings** page. |
| AI explanation "not configured" / "rate limited" | Set `GROQ_API_KEY`, or wait for your Groq account's rate limit to reset. Scans still complete deterministically. |
| `npm ci` lockfile errors | Use npm 11 (`npm i -g npm@11`). The lockfile was generated with npm 11.5. |
| Psycopg/Proactor errors on Windows | The project uses `asyncpg`, which works on Windows. Make sure `DATABASE_URL` does not force `+psycopg`. |

## Known limitations

These are stated honestly:

- **Detection limits.** Rules and heuristics catch common patterns, not every scam. Some legitimate messages will trigger indicators. Scores are evidence indices, not probabilities.
- **No reputation data.** No live URL reputation or threat-intelligence feed is connected. Reputation is shown as *not configured*, and URLs are never visited.
- **Classifier scope.** The ML baseline was trained on 2011–2012 SMS spam. It measures spam-like wording, not modern scam categories, and it is English-centric.
- **Groq reliability.** With `openai/gpt-oss-20b`, strict structured output intermittently returned `json_validate_failed` in testing. The service retries once in JSON-object mode, still under Pydantic validation, and otherwise falls back to templates. Availability and rate limits depend on your Groq account.
- **Single operator, single process.** There are no multi-user accounts; token mode protects a single-operator deployment. Rate limiting, the WebSocket hub and the demo runner are in-process, so run one backend instance. Redis would be needed to scale out.
- **Simulated security events.** Failed-login, suspicious-login and account-takeover events are synthetic simulations. There are no real identity-provider integrations.
- **No Content-Security-Policy on the frontend yet.** Other security headers are set.

## License and data attribution

The ML baseline uses the UCI SMS Spam Collection (Almeida & Gómez Hidalgo, 2011), licensed CC BY 4.0. No license has been chosen for the project code yet.
