# Data model

The database is PostgreSQL, accessed through SQLAlchemy 2 (async, asyncpg). The schema is managed by Alembic in `backend/alembic/versions/`.

- **Identifiers:** all primary keys are UUIDs.
- **Timestamps:** timezone-aware UTC.
- **Enums:** stored as constrained `VARCHAR` with `CHECK` constraints, so they stay portable.
- **JSON:** `JSONB` is used for the few variable-shape fields.

```
demo_runs 1───* scans 1───* scan_findings
    │            │ 1
    │            ├───* security_events *───1 incidents 1───* incident_notes
    │            └───* incidents (originating scan)
    └───* security_events / incidents (demo provenance)

audit_logs (entity_type, entity_id) → incidents | scans | events | demo_run | system
```

## Tables

### `scans`

| Column | Notes |
|---|---|
| `id`, `created_at` (indexed) | |
| `kind` | `message` or `url` |
| `content_type` | |
| `source` | `application`, `demo` or `simulation` (indexed) |
| `demo_run_id` | FK to `demo_runs`, SET NULL |
| `risk_score` | 0–100, enforced by a CHECK constraint |
| `risk_level` | |
| `evidence_strength` | |
| `summary` | Deterministic template text |
| `ai_summary` | Null unless `STORE_AI_SUMMARIES=true` |
| `recommendations`, `limitations`, `score_breakdown` | JSONB |
| `llm_status`, `llm_model`, `sent_to_llm` | |
| `classifier_status`, `classifier_version`, `classifier_probability` | |
| `rule_version`, `scoring_version` | |
| `input_length`, `url_count` | |
| `target_display` | For URL scans: scheme, host and port only |
| `expires_at` | Indexed; drives retention |

Index: `(risk_level, created_at)`.

**There is no column for raw message text.**

### `scan_findings`

Columns: `scan_id` (FK, CASCADE), `position`, `rule_id` (indexed), `title`, `category`, `severity`, `source`, `weight`, `points`, `explanation`, and `evidence_excerpt`. The excerpt is null unless `STORE_FINDING_EXCERPTS=true`.

### `security_events`

| Column | Notes |
|---|---|
| `event_type` | Indexed |
| `severity` | Indexed |
| `risk_score` | Nullable; 0–100 CHECK |
| `actor` | A synthetic or authorized identifier. Rate-limit events use a hashed client tag, never an IP. |
| `description` | At most 500 characters, never raw content |
| `source` | |
| `status` | `new`, `acknowledged` or `linked` |
| `details` | JSONB |
| `scan_id` | FK, SET NULL |
| `incident_id` | FK, SET NULL. This is the incident–event relationship: an event belongs to at most one incident. |
| `demo_run_id` | |

Index: `(source, created_at)`.

### `incidents`

Columns: `title`, `description`, `severity`, `risk_score`, `evidence_summary`, `status`, `resolution_notes`, `resolved_at`, `source`, `demo_run_id`, `scan_id`, `created_by` and `updated_at`. `status` is one of `OPEN`, `INVESTIGATING`, `RESOLVED` or `FALSE_POSITIVE`.

Index: `(status, created_at)`.

### `incident_notes`

Columns: `incident_id` (FK, CASCADE), `author`, `kind` and `body`. `kind` is `note`, `ai_summary` or `system`.

### `audit_logs`

Columns: `actor`, `action` (indexed), `entity_type`, `entity_id`, `details` (JSONB, which holds field names and status transitions but never note bodies), `request_id` and `source`.

Index: `(entity_type, entity_id)`.

### `demo_runs`

Columns: `scenario_id`, `status`, `steps` (JSONB progress), `started_at`, `finished_at` and `error`.

## Retention and privacy

- An hourly task deletes scans whose `expires_at` has passed. That is `created_at + SCAN_RETENTION_DAYS`, 30 days by default, and findings cascade with the scan.
- Security events beyond `EVENT_HISTORY_MAX` (default 5000) are pruned oldest-first, except events linked to incidents.
- `DELETE /scans/{id}` removes a scan immediately.
- Demo reset removes only `demo` and `simulation` provenance rows.

## Migrations

```bash
cd backend
alembic upgrade head          # apply
alembic check                 # verify models == migrations (run in CI)
alembic revision --autogenerate -m "describe change"   # after editing models
```

The application never creates tables automatically. In containers, `scripts/start.sh` runs `alembic upgrade head` when `RUN_MIGRATIONS_ON_START=true`. Tests build the schema with `metadata.create_all` against SQLite or a disposable PostgreSQL database.

To reset a local database, run `docker compose down -v`. This deletes the `pgdata` volume and **all local data**.
