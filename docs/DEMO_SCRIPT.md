# Demo script (about 3½ minutes)

**Before the demo:**
- Run `docker compose up` (or open the deployed site).
- Open **System health** and confirm the database is *Connected* and the WebSocket is *Live*. Groq shows *Active* or *Not configured*; the demo works either way.
- Go to **Attack replay → Reset demo data** so the dashboard starts clean.
- Keep two tabs open: **Dashboard** and **Analyzer**.

If Groq fails or rate-limits during the demo, the result card says so explicitly, for example "AI explanation unavailable: the provider did not respond in time". Point at that line. It shows the fallback is honest, and the score is unchanged because it never depended on the LLM.

---

**1. Landing (0:00–0:20).** Open `/`.

> "SentinelAI doesn't just say *scam*. It shows the evidence, scores it transparently, and turns detections into incidents. Rules and a measured ML model produce the score; Groq only explains."

**2. Message analysis (0:20–1:10).** Go to **Message analyzer**, click **Payment scam** (synthetic), leave **AI explanation** on, and click **Analyze**.
- Point at the score ring and the **CRITICAL** label.
  > "This is an evidence index, not an 80% fraud probability. We say that on the card."
- Scroll through the indicators: *Request for a one-time code*, *Raw IP address*, *Payment demand under time pressure*. Each one shows its source badge (Rule / URL check / ML model / AI) and the quoted evidence.
- Show the **AI explanation** card ("Groq · openai/gpt-oss-20b") and "AI corroborated" badges. Mention that AI claims whose quotes can't be found in the text are discarded.
- Show **Score breakdown**: category caps and diminishing returns.
- Click **Security event published** to show that it linked through.

**3. URL analysis (1:10–1:40).** Go to **URL analyzer** and click the `xn--pypal-4ve.com` example.
- Point out *Internationalized (punycode) domain*, *Mixed alphabets in one domain label* and *Lookalike of 'paypal'*.
  > "We never visit the URL; reputation is honestly 'not configured'."
- Then try `https://www.wikipedia.org/`, which stays LOW. That's the false-positive discipline.

**4. Live attack replay (1:40–2:40).** Go to **Dashboard**, then open **Attack replay** in a second window (or use split screen).
- Click **Start scenario** on *Phishing-led account takeover*. Steps tick through as the real pipeline runs: phishing SMS analyzed, failed-login burst, suspicious login, account-takeover warning, incident opened.
- On the dashboard, events arrive **live over WebSocket**, each labelled *Demo*, and the counters update.
- Click **Investigate incident →**.

**5. Incident response (2:40–3:20).**
- Review the evidence summary, linked events and the **timeline**.
- Click **Summarize with Groq**. The result is stored as an *AI-generated* note.
- Add a note: "Reset user credentials; blocked sender."
- Set the status to **RESOLVED**. The form requires resolution notes; type them and save.
- Open **Audit trail** and show every change, with actor and request ID.

**6. Wrap-up (3:20–3:40).**

> "Architecture: Next.js on Vercel, FastAPI and Postgres on Render, Groq server-side with strict schemas and a deterministic fallback, 166 backend tests and 5 browser E2E flows. Limits are on the System health page and in the README: no live threat intel, an SMS-era classifier, and simulated login telemetry."

---

**Backup plan:**
- **No network:** run locally with `GROQ_ENABLED=false`. Everything except the AI cards works.
- **Database empty:** run `docker compose exec backend python -m scripts.seed` to load the three labelled demo scenarios.
