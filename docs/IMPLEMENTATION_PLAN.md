# Implementation plan and status

## Starting point

The repository was empty. The toolchain available was Node 22.13 / npm 11.5, Python 3.12, Docker 29 with Compose v5, and git. The Groq model and its structured-output support were checked against console.groq.com documentation: `openai/gpt-oss-20b` is a production model with strict `json_schema` support.

## Checklist

| Phase | Item | Status |
|---|---|---|
| 0 Inspect | Repository, runtimes, registries, Docker | ✅ |
| 1 Plan | Architecture, scoring, schemas, API, security model | ✅ (docs/) |
| 2 Foundation | FastAPI app, settings validation, middleware, error envelope, health and readiness | ✅ |
| | Next.js 16 app, design tokens, shell, API client, providers | ✅ |
| | PostgreSQL + SQLAlchemy async + Alembic initial migration | ✅ |
| 3 Detection | 20 message rules + 6 combinations, negation guard, obfuscation folding | ✅ |
| | Offline URL analyzer (25 checks), no network I/O (tested) | ✅ |
| | Scoring engine (dedup, caps, diminishing returns, thresholds, evidence strength) | ✅ |
| 4 Groq | Service: strict schema, Pydantic validation, timeouts, retries, budget, error classes, fallback | ✅ |
| | Prompt-injection defenses, evidence grounding, data minimization | ✅ |
| | `json_validate_failed` retry in JSON-object mode | ✅ (unit-tested; not yet seen live after the change) |
| | Incident AI summary, live connectivity check | ✅ |
| 5 Persistence/API | Scans, history, delete, dashboard summary and activity, events, incidents, notes, links, audit | ✅ |
| 6 Frontend | Landing, dashboard, analyzers, history, events, incidents, replay, system health, settings | ✅ |
| 7 Real-time | WebSocket hub, origin check, token auth frame, reconnect and backoff, polling fallback | ✅ |
| | Demo scenarios (3) through the real pipeline, cancel, simulator, safe reset, seed script | ✅ |
| 8 ML | Dataset provenance, de-duplication, leakage check, training, held-out metrics, JSON export, parity test | ✅ |
| 9 Hardening | Rate limits, body limits, security headers, CORS, auth modes, privacy defaults, retention | ✅ |
| 10 Deploy | Dockerfiles, docker-compose, render.yaml, Vercel instructions, CI workflow, docs, demo script | ✅ |

## Not implemented / pending

- **Accounts.** There are no multi-user accounts, sessions or roles; the design is single-operator with token auth.
- **External reputation and threat-intel providers.** There is an interface only. The status is honestly reported as not configured.
- **Scaling.** There is no Redis, so the backend is limited to one instance.
- **Frontend CSP.** No Content-Security-Policy header is set yet.
- **Unverified deployment.** The Render and Vercel setup has **not** been deployed or verified from this environment. It requires your accounts. The Docker images it uses were built and run locally.
- **GitHub Actions.** The workflow is written but has not been run, because the repository has no remote yet.
- **Classifier coverage.** The classifier has not been evaluated on modern scam data; no such licensed dataset was used.
- **Frontend dependency advisories.** `npm audit` reports advisories in dev tooling dependencies. They have not been triaged.

## Test results

These are actual runs on 2026-10-19 (Windows 11, Docker Desktop):

| Check | Command | Result |
|---|---|---|
| Backend lint | `ruff check app ml tests` / `ruff format --check app` | passed |
| Backend types | `mypy app` | no issues in 61 files |
| Backend tests (SQLite) | `pytest -q` | **166 passed** |
| Backend tests (PostgreSQL 17) | `TEST_DATABASE_URL=… pytest -q` | **166 passed** |
| Migrations | `alembic upgrade head` → `alembic check` → `alembic downgrade base` | applied; no drift; downgrade OK |
| Frontend lint | `eslint .` | passed |
| Frontend types | `tsc --noEmit` (strict) | passed |
| Frontend unit tests | `vitest run` | **27 passed** |
| Frontend build | `next build` | passed; 11 routes prerendered |
| Docker | `docker compose up --build` | db, backend and frontend healthy; migrations applied on start |
| E2E (Playwright, Chromium) | `npx playwright test` against compose | **5 passed** (4 workflows + mobile) |
| Seed | `python -m scripts.seed` in container | 3/3 scenarios completed |
| Live Groq | `POST /system/llm-check` with the configured key | `ok`, schema-valid output, about 0.5–1.1 s |

The four required end-to-end workflows are covered:
1. Message → rules → optional Groq → score → results (E2E 1, plus `test_scan_api.py`).
2. URL → offline checks → score → results (E2E 2, plus `test_url_analyzer.py`, including a no-network test).
3. Demo event → persisted → WebSocket → displayed (E2E 3, plus `test_websocket.py`).
4. Incident → note → resolve → audit history (E2E 4, plus `test_incidents.py`).

**Observed issue.** With live Groq, the strict structured output intermittently returned `400 json_validate_failed` (about half of the calls in one probe). A single retry in JSON-object mode was added. A heavy probe also hit the account's `429` rate limit, which the app reports as `rate_limited` and handles with the deterministic fallback.

## Résumé-ready description

**SentinelAI: explainable scam and threat-analysis platform.** Next.js 16, TypeScript, FastAPI, PostgreSQL, Groq, scikit-learn, WebSockets, Docker.

- Built a full-stack cybersecurity app that detects social-engineering messages and phishing URLs. It combines 20 deterministic indicators, 25 offline URL heuristics (homographs, typosquats, obfuscated IPs) and a TF-IDF/logistic-regression baseline (held-out F1 0.94, 0.9% false-positive rate) into a reproducible, capped, explainable 0–100 risk score.
- Integrated a Groq-hosted LLM for plain-language explanations. It uses strict JSON-schema outputs, Pydantic validation, evidence-quote grounding, data minimization and prompt-injection defenses. The deterministic fallback keeps the product fully functional without the LLM.
- Implemented real-time security monitoring: persisted events broadcast over WebSockets, an incident workflow with timelines and an audit trail, and safe synthetic attack-replay scenarios that run through the production pipeline.
- Shipped with 166 backend tests (SQLite and PostgreSQL), 27 frontend unit tests, 5 Playwright E2E flows, Alembic migrations, Docker Compose, CI, and deployment configuration for Render and Vercel.
