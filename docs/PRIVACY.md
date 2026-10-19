# Privacy

## What is collected

| Data | Stored? | Notes |
|---|---|---|
| Message text you submit | **No** | It is analyzed in memory only. The `scans` table has no text column. |
| Evidence excerpts (≤160 characters around a match) | Off by default | Turned on with `STORE_FINDING_EXCERPTS=true`. |
| AI-written summary of a scan | Off by default | Turned on with `STORE_AI_SUMMARIES=true`. The summary may paraphrase the content. |
| URL you submit | Partially | Only `scheme://host[:port]` is stored. Paths and query strings, which may contain tokens, are not. |
| Scan metadata | Yes | Score, level, findings (rule IDs, titles, points), versions, input length, timestamps. |
| Incident notes | Yes | Written by the operator. |
| Security events | Yes | Descriptions contain titles and indicators, never submitted content. Rate-limit events use a hashed client tag, not an IP. |
| Application logs | Metadata only | Method, path (no query string), status, duration, request ID, and LLM status and latency. Never bodies or content. |

## Data sent to Groq

Data goes to Groq only when **AI explanation** is enabled for a request and the server has `GROQ_API_KEY` set:

- **Message scans** send the normalized text with **long digit sequences masked** (`[NUMBER]`: OTPs, card, account and phone numbers) and **e-mail addresses masked** (`[EMAIL]`). The text is truncated to `GROQ_MAX_INPUT_CHARS` (default 4000), and the rule IDs that fired are included.
- **URL scans** send the URL **without its query string**, plus the extracted feature list.
- **Incident summaries** send structured incident metadata only: title, severity, evidence summary, event descriptions and analyst notes. Raw scanned messages are never stored, so they are never sent.

Groq processes this data under the Groq account's terms. Retention and training policies are set by Groq and the account configuration; check them at https://groq.com before use. SentinelAI does not store prompts or raw responses.

The UI states before submission what will be sent. The **AI explanation** switch defaults to on for messages and off for URLs. The server operator can disable it globally with `GROQ_ENABLED=false`.

## Retention and deletion

- Scans expire after `SCAN_RETENTION_DAYS` (default 30) and are purged hourly. Findings are deleted with their scan.
- Any scan can be deleted immediately via **Scan history → Delete record**, or with `DELETE /api/v1/scans/{id}`.
- Event history is bounded by `EVENT_HISTORY_MAX`.
- Demo and simulation data can be wiped from **Attack replay → Reset demo data**.
- The operator token is kept in the browser's `sessionStorage`, which is cleared when the tab closes. The app sets no cookies.

## User guidance

Never paste real passwords, OTPs, PINs, CVVs, API keys or authentication tokens. SentinelAI never needs them, and the UI repeats this warning.
