"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Activity, ArrowRight, BrainCircuit, ClipboardList, Database, Globe, Layers, Link2, Mail, MonitorSmartphone,
  QrCode, Radio, Scale, ScanSearch, Server, Sparkles,
} from "lucide-react";
import type { ReactNode } from "react";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState, Skeleton } from "@/components/ui/states";
import { api } from "@/lib/api";
import { humanize } from "@/lib/utils";

const PIPELINE = [
  { icon: ScanSearch, title: "Input", text: "Message, URL, QR code or e-mail headers" },
  { icon: Layers, title: "Normalize", text: "Unicode clean-up, hidden characters, link extraction" },
  { icon: Scale, title: "Detect", text: "20 message rules + 25 URL checks + combinations" },
  { icon: Globe, title: "Enrich", text: "VirusTotal vendors + ML spam model" },
  { icon: Sparkles, title: "Explain", text: "Groq LLM writes a plain-English summary" },
  { icon: Activity, title: "Score", text: "Capped, deduplicated 0–100 evidence index" },
  { icon: Radio, title: "Respond", text: "Events stream live → incidents → audit trail" },
];

const COMPONENTS: { icon: typeof Server; name: string; tech: string; what: ReactNode }[] = [
  { icon: MonitorSmartphone, name: "Web app", tech: "Next.js 16 · React 19 · Tailwind",
    what: "Everything you click. It never decides anything itself — it calls the API and draws the answer (scores, highlights, charts, timelines)." },
  { icon: Server, name: "API server", tech: "FastAPI · Python 3.12",
    what: "The brain. Receives requests, runs the detection pipeline, enforces rate limits, validates every input and output, and stores results." },
  { icon: Scale, name: "Rule engine", tech: "app/services/detection",
    what: "Hand-written, documented detectors for scam language (OTP requests, threats, fees, impersonation, prompt injection…) and URL tricks (lookalikes, hidden IPs, punycode…). Each one says which words triggered it." },
  { icon: Activity, name: "Scoring engine", tech: "app/services/scoring",
    what: "Adds up evidence fairly: each rule counts once, weaker rules in the same category count half, and every category has a cap so no single signal dominates. Result: a reproducible 0–100 score." },
  { icon: Globe, name: "VirusTotal", tech: "External threat intel (optional)",
    what: "Asks 90+ security vendors whether they already know a link is malicious. We look the URL up by ID — we never open it. Results are cached to save your free quota." },
  { icon: BrainCircuit, name: "ML classifier", tech: "TF-IDF + logistic regression",
    what: "A small statistical model trained on 5,000 real SMS messages (F1 0.94). It adds at most 12 points — a second opinion, never the decider." },
  { icon: Sparkles, name: "Groq LLM", tech: "openai/gpt-oss-20b (optional)",
    what: "Explains the evidence in plain English. Its claims are thrown away unless they quote the real message, and it can't lower a score. Works without it." },
  { icon: Database, name: "Database", tech: "PostgreSQL + Alembic",
    what: "Stores scan results (never the raw message), security events, incidents, notes and a full audit trail." },
  { icon: Radio, name: "Live event stream", tech: "WebSocket",
    what: "When something high-risk happens, the server pushes it to every open dashboard instantly — no refresh needed." },
  { icon: ClipboardList, name: "Incident center", tech: "Triage workflow",
    what: "High-risk findings become incidents you can investigate, annotate, summarize with AI, resolve and export as a report." },
];

const TOOLS = [
  { icon: ScanSearch, name: "Message analyzer", text: "SMS, e-mail, chat, job offers — with an evidence map of the exact words." },
  { icon: Link2, name: "URL analyzer", text: "URL X-ray + VirusTotal vendor verdicts. Never visits the link." },
  { icon: QrCode, name: "QR scanner", text: "Decodes QR codes in the browser and checks the hidden link (quishing)." },
  { icon: Mail, name: "E-mail forensics", text: "SPF / DKIM / DMARC, reply-to tricks, display-name spoofing." },
];

const URL_RULES = [
  ["Text before '@' (user-info trick)", 30], ["Obfuscated IP address", 30], ["Mixed alphabets in a domain", 30],
  ["Lookalike / typosquat domain", 35], ["Brand only in the subdomain", 28], ["Raw IP address", 22],
  ["Brand in an unrelated domain", 18], ["Direct link to an installer", 18], ["Punycode domain", 15],
  ["Percent-encoded host", 15], ["Internal network address", 15], ["Unusual encoding", 12], ["Non-standard port", 12],
  ["URL shortener", 10], ["Embedded redirect", 10], ["Many subdomains", 10], ["Unencrypted HTTP", 8],
  ["Account wording in URL", 8], ["Abused TLD", 8], ["Very long URL", 5],
] as const;

const DIFFERENCES = [
  ["“Scam / not scam” black box", "Every point is traced to a named rule and the exact words that triggered it"],
  ["One ML model decides", "Rules drive the score; ML is capped at 12 points"],
  ["LLM makes things up", "AI claims must quote the message or they're discarded"],
  ["Reputation-only link checks", "Offline URL X-ray + VirusTotal, combined and capped"],
  ["Detection ends at a verdict", "Verdict → live event → incident → audit trail"],
];

export default function HowItWorksPage() {
  const rules = useQuery({ queryKey: ["rules"], queryFn: api.rules, staleTime: Infinity });

  return (
    <>
      <PageHeader title="How SentinelAI works" description="Every part of the system, in plain language — and every rule, pulled live from the running code." />

      <section className="mb-10">
        <h2 className="mb-4 text-lg font-semibold">The pipeline</h2>
        <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-7">
          {PIPELINE.map(({ icon: Icon, title, text }, i) => (
            <li key={title} className="relative flex flex-col gap-2 rounded-xl border border-border bg-surface p-4">
              <span className="flex items-center gap-2 text-xs font-semibold text-accent">
                <span className="flex size-6 items-center justify-center rounded-full bg-accent/15">{i + 1}</span>
                <Icon className="size-4" aria-hidden />
              </span>
              <span className="text-sm font-semibold">{title}</span>
              <span className="text-xs leading-relaxed text-muted">{text}</span>
              {i < PIPELINE.length - 1 && <ArrowRight className="absolute top-1/2 -right-2.5 hidden size-4 text-subtle lg:block" aria-hidden />}
            </li>
          ))}
        </ol>
      </section>

      <section className="mb-10">
        <h2 className="mb-4 text-lg font-semibold">Four ways in</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {TOOLS.map(({ icon: Icon, name, text }) => (
            <div key={name} className="flex gap-3 rounded-xl border border-border bg-surface p-4">
              <Icon className="mt-0.5 size-5 shrink-0 text-accent" aria-hidden />
              <div><p className="text-sm font-semibold">{name}</p><p className="text-xs text-muted">{text}</p></div>
            </div>
          ))}
        </div>
      </section>

      <section className="mb-10">
        <h2 className="mb-4 text-lg font-semibold">What each component does</h2>
        <div className="grid gap-3 md:grid-cols-2">
          {COMPONENTS.map(({ icon: Icon, name, tech, what }) => (
            <Card key={name}>
              <CardContent className="flex gap-4 py-4">
                <div className="flex size-10 shrink-0 items-center justify-center rounded-lg border border-accent/20 bg-accent/10">
                  <Icon className="size-5 text-accent" aria-hidden />
                </div>
                <div>
                  <p className="flex flex-wrap items-center gap-2 text-sm font-semibold">{name} <Badge>{tech}</Badge></p>
                  <p className="mt-1 text-sm leading-relaxed text-muted">{what}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      <section className="mb-10 grid gap-5 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Message rules (live from the API)</CardTitle>
            <CardDescription>The weight is how many points a rule adds. Categories are capped; extra rules in a category count 50%.</CardDescription>
          </CardHeader>
          <CardContent>
            {rules.isError ? <ErrorState error={rules.error} /> : !rules.data ? <Skeleton className="h-64 w-full" /> : (
              <div className="max-h-[28rem] overflow-y-auto">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-surface text-muted"><tr><th className="py-2 font-medium">Rule</th><th className="font-medium">Category</th><th className="text-right font-medium">Weight</th></tr></thead>
                  <tbody>
                    {[...rules.data.message_rules].sort((a, b) => b.weight - a.weight).map((r) => (
                      <tr key={r.rule_id} className="border-t border-border" title={r.explanation}>
                        <td className="py-2 pr-2">{r.title}</td>
                        <td className="pr-2 text-muted">{humanize(r.category)}</td>
                        <td className="text-right"><span className="rounded bg-surface-3 px-1.5 py-0.5 font-mono">+{r.weight}</span></td>
                      </tr>
                    ))}
                    {rules.data.combination_rules.map((r) => (
                      <tr key={r.rule_id} className="border-t border-border" title={r.explanation}>
                        <td className="py-2 pr-2">{r.title}</td>
                        <td className="pr-2 text-muted">Combination</td>
                        <td className="text-right"><span className="rounded bg-risk-high/15 px-1.5 py-0.5 font-mono text-risk-high">+{r.weight}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Risk levels</CardTitle><CardDescription>An evidence index — not a probability.</CardDescription></CardHeader>
          <CardContent className="flex flex-col gap-2 text-sm">
            {rules.data && [
              ["LOW", `0 – ${rules.data.thresholds.medium - 1}`, "bg-risk-low"],
              ["MEDIUM", `${rules.data.thresholds.medium} – ${rules.data.thresholds.high - 1}`, "bg-risk-medium"],
              ["HIGH", `${rules.data.thresholds.high} – ${rules.data.thresholds.critical - 1}`, "bg-risk-high"],
              ["CRITICAL", `${rules.data.thresholds.critical} – 100`, "bg-risk-critical"],
            ].map(([name, range, color]) => (
              <div key={name} className="flex items-center gap-3"><span className={`size-3 rounded-sm ${color}`} /><span className="w-20 font-medium">{name}</span><span className="text-muted tabular-nums">{range}</span></div>
            ))}
            <p className="mt-3 text-xs text-muted">HIGH and CRITICAL results publish a live security event. CRITICAL results also open an incident automatically.</p>
          </CardContent>
        </Card>
      </section>

      <section className="mb-10">
        <h2 className="mb-4 text-lg font-semibold">URL checks — done offline</h2>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {URL_RULES.map(([title, weight]) => (
            <div key={title} className="flex items-center justify-between gap-2 rounded-lg border border-border bg-surface px-3 py-2 text-xs">
              <span>{title}</span><span className="font-mono text-muted">+{weight}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="mb-4">
        <h2 className="mb-4 text-lg font-semibold">What makes it different</h2>
        <div className="grid gap-3">
          {DIFFERENCES.map(([old, now]) => (
            <div key={old} className="grid gap-2 rounded-xl border border-border bg-surface p-4 text-sm sm:grid-cols-2">
              <span className="text-muted"><Badge tone="critical" className="mr-2">Typical</Badge>{old}</span>
              <span><Badge tone="low" className="mr-2">SentinelAI</Badge>{now}</span>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
