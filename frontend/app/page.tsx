import {
  Activity,
  BrainCircuit,
  ClipboardList,
  FileSearch,
  Gauge,
  LayoutDashboard,
  Link2,
  Lock,
  PlayCircle,
  ShieldHalf,
  Sparkles,
  Scale,
} from "lucide-react";
import Link from "next/link";

import { buttonVariants } from "@/components/ui/button";

const FEATURES = [
  { icon: FileSearch, title: "Message scam analyzer", text: "Deterministic rules detect credential requests, payment pressure, impersonation, prompt injection and more — each finding shows its evidence." },
  { icon: Link2, title: "Offline URL analysis", text: "Lookalike domains, punycode homographs, disguised IPs, user-info tricks and encoding anomalies — without ever visiting the link." },
  { icon: Sparkles, title: "Groq-powered explanations", text: "An LLM explains the evidence in plain language. Its output is schema-validated, quote-checked and cannot set the score." },
  { icon: Scale, title: "Explainable risk score", text: "Documented weights, per-category caps and deduplication produce a reproducible 0–100 evidence index." },
  { icon: BrainCircuit, title: "Measured ML baseline", text: "A TF-IDF + logistic-regression model with held-out metrics adds a bounded, transparent signal." },
  { icon: Activity, title: "Real-time event stream", text: "High-risk detections become persisted security events, broadcast to the dashboard over WebSocket." },
  { icon: ClipboardList, title: "Incident management", text: "Triage, notes, status workflow, timelines and a full audit trail." },
  { icon: PlayCircle, title: "Safe attack replay", text: "Synthetic scenarios run through the real pipeline to demonstrate detection-to-resolution." },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen">
      <header className="mx-auto flex max-w-6xl items-center justify-between px-4 py-5 sm:px-6">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <ShieldHalf className="size-6 text-accent" aria-hidden />
          <span>Sentinel<span className="text-accent">AI</span></span>
        </Link>
        <nav aria-label="Primary" className="flex items-center gap-2">
          <Link href="/dashboard" className={buttonVariants({ variant: "ghost", size: "sm" })}>Dashboard</Link>
          <Link href="/analyze" className={buttonVariants({ variant: "primary", size: "sm" })}>Open app</Link>
        </nav>
      </header>

      <main>
        <section className="mx-auto max-w-6xl px-4 pt-12 pb-16 sm:px-6 sm:pt-20">
          <p className="mb-4 inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/10 px-3 py-1 text-xs text-accent">
            <Gauge className="size-3.5" aria-hidden /> AI for Cybersecurity & Digital Safety
          </p>
          <h1 className="max-w-3xl text-4xl font-semibold tracking-tight sm:text-5xl">
            Know why a message or link is dangerous — not just that it might be.
          </h1>
          <p className="mt-5 max-w-2xl text-lg leading-relaxed text-muted">
            SentinelAI combines deterministic security rules, a measured ML baseline and validated LLM explanations into
            an evidence-driven risk score — then turns high-risk detections into live security events and incidents.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link href="/analyze" className={buttonVariants({ size: "lg" })}><FileSearch aria-hidden /> Analyze a message</Link>
            <Link href="/urls" className={buttonVariants({ variant: "secondary", size: "lg" })}><Link2 aria-hidden /> Check a URL</Link>
            <Link href="/dashboard" className={buttonVariants({ variant: "outline", size: "lg" })}><LayoutDashboard aria-hidden /> Security dashboard</Link>
          </div>
        </section>

        <section aria-labelledby="pipeline" className="border-y border-border bg-surface/60">
          <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
            <h2 id="pipeline" className="mb-6 text-sm font-semibold tracking-wide text-muted uppercase">How it works</h2>
            <ol className="grid gap-3 text-sm sm:grid-cols-3 lg:grid-cols-7">
              {["Analyze", "Detect", "Explain", "Score risk", "Recommend", "Create incident", "Monitor"].map((step, i) => (
                <li key={step} className="flex items-center gap-2 rounded-lg border border-border bg-surface-2 px-3 py-2">
                  <span className="flex size-6 items-center justify-center rounded-full bg-accent/15 text-xs font-semibold text-accent">{i + 1}</span>
                  {step}
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section aria-labelledby="features" className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
          <h2 id="features" className="mb-8 text-2xl font-semibold tracking-tight">What&apos;s inside</h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {FEATURES.map(({ icon: Icon, title, text }) => (
              <div key={title} className="rounded-xl border border-border bg-surface p-5">
                <Icon className="mb-3 size-5 text-accent" aria-hidden />
                <h3 className="mb-1.5 text-sm font-semibold">{title}</h3>
                <p className="text-sm leading-relaxed text-muted">{text}</p>
              </div>
            ))}
          </div>
        </section>

        <section aria-labelledby="privacy" className="mx-auto max-w-6xl px-4 pb-20 sm:px-6">
          <div className="grid gap-6 rounded-xl border border-border bg-surface p-6 md:grid-cols-2">
            <div>
              <h2 id="privacy" className="mb-3 flex items-center gap-2 text-lg font-semibold"><Lock className="size-5 text-accent" aria-hidden /> Privacy by default</h2>
              <ul className="list-disc space-y-2 pl-5 text-sm leading-relaxed text-muted">
                <li>Raw message text is never stored — only scores, findings and versions.</li>
                <li>AI explanation is optional; when used, numbers and e-mail addresses are masked before text is sent to Groq.</li>
                <li>URLs are never visited, and only their scheme and host are stored.</li>
                <li>Never paste real passwords, OTPs, PINs or card numbers.</li>
              </ul>
            </div>
            <div>
              <h2 className="mb-3 text-lg font-semibold">Honest limitations</h2>
              <ul className="list-disc space-y-2 pl-5 text-sm leading-relaxed text-muted">
                <li>Indicators are signals, not proof: no detector catches every scam, and legitimate messages can trigger rules.</li>
                <li>The score is an evidence index, not a probability of fraud.</li>
                <li>No live threat-intelligence or domain-reputation feed is connected.</li>
                <li>Demo and simulated events are synthetic and clearly labelled.</li>
              </ul>
            </div>
          </div>
        </section>
      </main>
      <footer className="border-t border-border py-6 text-center text-xs text-subtle">
        SentinelAI · hackathon project · not a substitute for professional security advice
      </footer>
    </div>
  );
}
