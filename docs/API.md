# API reference

- **Base URL:** `{host}/api/v1`
- **Interactive OpenAPI:** `{host}/docs`, with the raw schema at `{host}/openapi.json`.

## Authentication

| `AUTH_MODE` | Behaviour |
|---|---|
| `open` | No credentials. For local development or an explicitly acknowledged public demo. Production refuses to start in this mode unless `ALLOW_OPEN_MODE_IN_PRODUCTION=true`. |
| `token` | Every endpoint except `/health`, `/api/v1/health/ready` and `/api/v1/auth/session` requires `Authorization: Bearer <ADMIN_API_TOKEN>`. |

Because the token travels in a header and never in a cookie, CSRF does not apply. The deployment is single-operator: there are no per-user resources, so cross-user ID tampering does not arise. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Errors

Every error uses one envelope. Submitted values are never echoed back.

```json
{
  "error": {
    "code": "validation_error",
    "message": "Request validation failed",
    "request_id": "3f2c…",
    "details": [{ "loc": ["body", "text"], "msg": "…", "type": "…" }]
  }
}
```

| Code | Meaning |
|---|---|
| `validation_error`, `invalid_url` | Invalid input (422). |
| `unauthorized` | Missing or invalid token (401). |
| `demo_disabled` | Demo endpoints are disabled (403). |
| `not_found` | Unknown resource (404). |
| `conflict` | Request conflicts with current state (409). |
| `payload_too_large` | Body exceeds `MAX_REQUEST_BYTES` (413). |
| `rate_limited` | Too many requests (429). Includes the `Retry-After` header and `details.retry_after_seconds`. |
| `internal_error` | Unexpected server error (500). |

Every response carries an `X-Request-ID` header. A valid incoming `X-Request-ID` is propagated.

## Health

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | Liveness: `{"status":"ok","version":"1.0.0"}` |
| GET | `/api/v1/health/ready` | Readiness: 200 `{"status":"ready","database":"ok"}`, or 503 |
| GET | `/api/v1/system/status` | Versions, DB, Groq status (never the key), classifier metrics, privacy configuration |
| POST | `/api/v1/system/llm-check` | Sends one synthetic request to Groq to verify credentials |
| GET | `/api/v1/auth/session` | `{"auth_mode","authenticated","token_required"}` |

## Scans

### `POST /api/v1/scans/message`

```json
{ "text": "URGENT: share the OTP to keep your account active", "content_type": "auto", "use_llm": true }
```

`content_type` accepts: `auto | sms | email | job_offer | payment_request | account_verification | delivery | prize | chat | general`.

Response (abridged):

```json
{
  "id": "…", "kind": "message", "content_type": "account_verification", "source": "application",
  "risk_score": 69, "risk_level": "HIGH", "evidence_strength": "strong",
  "summary": "This message shows several strong warning signs (score 69/100, HIGH): …",
  "ai_summary": "…or null",
  "findings": [{ "rule_id": "MSG_CREDENTIAL_OTP", "title": "Request for a one-time code", "category": "credential_request",
                 "severity": "high", "source": "rule", "weight": 30, "points": 30, "explanation": "…",
                 "evidence": "…share the OTP to keep…", "match_count": 1, "corroborated_by": ["llm"] }],
  "recommendations": ["…"], "limitations": ["…"],
  "score_breakdown": [{ "category": "credential_request", "rule_ids": ["MSG_CREDENTIAL_OTP"], "raw": 30, "cap": 40, "points": 30 }],
  "llm": { "status": "ok", "model": "openai/gpt-oss-20b", "used": true, "signals_accepted": 2, "signals_discarded": 0, "latency_ms": 900 },
  "classifier": { "status": "available", "model_version": "sms-tfidf-lr-1.0", "spam_probability": 0.74, "points": 6 },
  "versions": { "rule_version": "msg-rules-1.0+url-rules-1.0", "scoring_version": "score-1.0", "classifier_version": "sms-tfidf-lr-1.0" },
  "privacy": { "raw_text_stored": false, "excerpts_stored": false, "sent_to_llm": true },
  "related_event_id": "…", "related_incident_id": null
}
```

Possible `llm.status` values: `ok | skipped | disabled | not_configured | rate_limited | timeout | provider_error | auth_error | invalid_output`.

### `POST /api/v1/scans/url`

```json
{ "url": "http://paypa1-secure-login.xyz/verify", "use_llm": false }
```

The response has the same shape as a message scan, plus `url_details`. It includes `reputation: {"status": "not_configured"}`. The URL is never fetched.

### History

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/scans?page=&page_size=&kind=&risk_level=&source=` | Paginated summaries |
| GET | `/api/v1/scans/{id}` | Stored detail and findings (no raw text) |
| DELETE | `/api/v1/scans/{id}` | Returns 204. The deletion is audited. |

## Dashboard and events

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/dashboard/summary` | Counts, risk distribution, recent scans/events, open incidents |
| GET | `/api/v1/dashboard/activity?range=24h\|7d` | Hourly or daily buckets per risk level, plus event counts |
| GET | `/api/v1/events?page=&severity=&event_type=&source=&status=&q=` | Paginated |
| GET | `/api/v1/events/{id}` | One event |
| PATCH | `/api/v1/events/{id}` | `{"status":"acknowledged"}` |
| WS | `/api/v1/ws/events` | Message types are listed in [ARCHITECTURE.md](ARCHITECTURE.md#websocket-flow) |

## Incidents

| Method | Path | Body |
|---|---|---|
| GET | `/api/v1/incidents?status=&severity=&source=&q=&page=` | |
| POST | `/api/v1/incidents` | `{title, severity, description?, evidence_summary?, risk_score?, scan_id?, event_ids?}` |
| GET | `/api/v1/incidents/{id}` | Detail with notes, events, timeline and audit |
| PATCH | `/api/v1/incidents/{id}` | `{status?, severity?, title?, description?, resolution_notes?}` (see note) |
| POST | `/api/v1/incidents/{id}/notes` | `{body}` |
| POST | `/api/v1/incidents/{id}/events` | `{event_ids: [...]}`. Returns 409 if an event is already linked elsewhere. |
| POST | `/api/v1/incidents/{id}/ai-summary` | Groq summary saved as an AI-labelled note |

For `PATCH`, moving to `RESOLVED` or `FALSE_POSITIVE` requires `resolution_notes`.

## Demo

All demo endpoints return 403 when `DEMO_MODE_ENABLED=false`.

| Method | Path |
|---|---|
| GET | `/api/v1/demo/scenarios` |
| POST | `/api/v1/demo/scenarios/{id}/run` (202; 409 if a run is active) |
| GET | `/api/v1/demo/scenarios/{id}/status` |
| POST | `/api/v1/demo/runs/{run_id}/cancel` |
| POST | `/api/v1/demo/events` `{"event_type": "failed_login_burst" \| "suspicious_login" \| "account_takeover_warning" \| "rate_limit" \| "high_risk_message" \| "high_risk_url"}` |
| GET | `/api/v1/demo/simulator` |
| POST | `/api/v1/demo/simulator/start` `{interval_seconds}` |
| POST | `/api/v1/demo/simulator/stop` |
| POST | `/api/v1/demo/reset` (deletes demo and simulation rows only) |

## Limits

- **Bodies:** at most 64 KiB. Messages are limited to 10 000 characters and URLs to 2048.
- **Rate limits** are per client IP, per minute: scans 30, writes 60, reads 300. All are configurable.
