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
  ArrowRight,
  Zap,
  Eye,
} from "lucide-react";
import Link from "next/link";

import { buttonVariants } from "@/components/ui/button";

const PIPELINE = ["Analyze", "Detect", "Explain", "Score risk", "Recommend", "Create incident", "Monitor"];

const FEATURES = [
  {
    icon: FileSearch,
    title: "Message scam analyzer",
    text: "20 documented indicators: credential/OTP requests, payment pressure, impersonation, prompt injection, hidden characters and more. Every finding shows its evidence.",
    href: "/analyze",
    cta: "Analyze a message",
  },
  {
    icon: Link2,
    title: "Offline URL analysis",
    text: "Lookalike domains, punycode homographs, disguised IPs, user-info tricks, shorteners and encoding anomalies — without ever visiting the link.",
    href: "/urls",
    cta: "Check a URL",
  },
  {
    icon: Sparkles,
    title: "Groq-powered explanations",
    text: "An LLM explains the evidence in plain language. Its output is schema-validated, quote-checked and cannot set the score — it only explains it.",
    href: "/system-health",
    cta: "View system status",
  },
  {
    icon: Scale,
    title: "Explainable risk score",
    text: "Documented weights, per-category caps and deduplication produce a reproducible 0–100 evidence index. Every point is traceable to a rule.",
    href: "/dashboard",
    cta: "Open dashboard",
  },
  {
    icon: BrainCircuit,
    title: "Measured ML baseline",
    text: "TF-IDF + logistic regression with held-out F1 of 0.94 and 0.9% false-positive rate. Capped at 12 points so it can't dominate the score.",
    href: "/system-health",
    cta: "View metrics",
  },
  {
    icon: Activity,
    title: "Real-time event stream",
    text: "High-risk detections become persisted security events, broadcast to the dashboard over WebSocket with automatic polling fallback.",
    href: "/events",
    cta: "View events",
  },
  {
    icon: ClipboardList,
    title: "Incident management",
    text: "Triage, annotate, resolve or mark false positive. Full audit trail, timeline, linked events and optional Groq incident summary.",
    href: "/incidents",
    cta: "Incident center",
  },
  {
    icon: PlayCircle,
    title: "Safe attack replay",
    text: "Three synthetic scenarios run through the real detection pipeline. Events stream in live and an incident opens — then reset with one click.",
    href: "/replay",
    cta: "Run a scenario",
  },
];

const STATS = [
  { value: "20", label: "Detection rules", icon: Eye },
  { value: "0–100", label: "Evidence score", icon: Scale },
  { value: "0.94", label: "Classifier F1", icon: BrainCircuit },
  { value: "Live", label: "WebSocket stream", icon: Zap },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen">
      {/* Nav */}
      <header className="mx-auto flex max-w-6xl items-center justify-between px-4 py-5 sm:px-6">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <ShieldHalf className="size-6 text-accent" aria-hidden />
          <span>Sentinel<span className="text-accent">AI</span></span>
        </Link>
        <nav aria-label="Primary" className="flex items-center gap-2">
          <Link href="/dashboard" className={buttonVariants({ variant: "ghost", size: "sm" })}>Dashboard</Link>
          <Link href="/analyze" className={buttonVariants({ variant: "primary", size: "sm" })}>
            Open app <ArrowRight className="size-3.5" aria-hidden />
          </Link>
        </nav>
      </header>

      <main>
        {/* Hero */}
        <section className="mx-auto max-w-6xl px-4 pt-14 pb-20 sm:px-6 sm:pt-24">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/10 px-3 py-1 text-xs text-accent">
            <Gauge className="size-3.5" aria-hidden />
            AI for Cybersecurity &amp; Digital Safety
          </div>
          <h1 className="max-w-3xl text-4xl font-semibold tracking-tight sm:text-6xl leading-tight">
            Know <span className="text-accent">why</span> a message<br className="hidden sm:block" /> or link is dangerous.
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-relaxed text-muted">
            SentinelAI combines deterministic security rules, a measured ML baseline and validated LLM explanations
            into an evidence-driven risk score — then turns high-risk detections into live security events and incidents.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link href="/analyze" className={buttonVariants({ size: "lg" })}>
              <FileSearch aria-hidden /> Analyze a message
            </Link>
            <Link href="/urls" className={buttonVariants({ variant: "secondary", size: "lg" })}>
              <Link2 aria-hidden /> Check a URL
            </Link>
            <Link href="/dashboard" className={buttonVariants({ variant: "outline", size: "lg" })}>
              <LayoutDashboard aria-hidden /> Security dashboard
            </Link>
          </div>
        </section>

        {/* Stats strip */}
        <section className="border-y border-border bg-surface/60">
          <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
            <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              {STATS.map(({ value, label, icon: Icon }) => (
                <div key={label} className="flex flex-col items-center gap-2 rounded-xl border border-border bg-surface-2 px-4 py-5 text-center">
                  <Icon className="size-5 text-accent" aria-hidden />
                  <dt className="text-2xl font-semibold tabular-nums">{value}</dt>
                  <dd className="text-xs text-muted">{label}</dd>
                </div>
              ))}
            </dl>
          </div>
        </section>

        {/* Pipeline */}
        <section aria-labelledby="pipeline" className="mx-auto max-w-6xl px-4 py-12 sm:px-6">
          <h2 id="pipeline" className="mb-6 text-xs font-semibold tracking-widest text-muted uppercase">How it works</h2>
          <ol className="grid gap-2 text-sm sm:grid-cols-4 lg:grid-cols-7">
            {PIPELINE.map((step, i) => (
              <li key={step} className="flex items-center gap-2.5 rounded-lg border border-border bg-surface-2 px-3 py-2.5">
                <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-accent/15 text-xs font-semibold text-accent">
                  {i + 1}
                </span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
        </section>

        {/* Features grid */}
        <section aria-labelledby="features" className="mx-auto max-w-6xl px-4 pb-16 sm:px-6">
          <h2 id="features" className="mb-8 text-2xl font-semibold tracking-tight">What&apos;s inside</h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {FEATURES.map(({ icon: Icon, title, text, href, cta }) => (
              <div key={title} className="group flex flex-col rounded-xl border border-border bg-surface p-5 transition-colors hover:border-accent/40 hover:bg-surface-2">
                <Icon className="mb-3 size-5 text-accent" aria-hidden />
                <h3 className="mb-1.5 text-sm font-semibold">{title}</h3>
                <p className="flex-1 text-sm leading-relaxed text-muted">{text}</p>
                <Link
                  href={href}
                  className="mt-4 inline-flex items-center gap-1 text-xs text-accent opacity-0 transition-opacity group-hover:opacity-100"
                >
                  {cta} <ArrowRight className="size-3" aria-hidden />
                </Link>
              </div>
            ))}
          </div>
        </section>

        {/* Privacy + limitations */}
        <section aria-labelledby="privacy" className="mx-auto max-w-6xl px-4 pb-20 sm:px-6">
          <div className="grid gap-6 rounded-xl border border-border bg-surface p-6 md:grid-cols-2">
            <div>
              <h2 id="privacy" className="mb-3 flex items-center gap-2 text-base font-semibold">
                <Lock className="size-4 text-accent" aria-hidden /> Privacy by default
              </h2>
              <ul className="list-disc space-y-2 pl-5 text-sm leading-relaxed text-muted">
                <li>Raw message text is never stored — only scores, findings and versions.</li>
                <li>AI explanation is optional; numbers and e-mail addresses are masked before text is sent to Groq.</li>
                <li>URLs are never visited, and only their scheme and host are stored.</li>
                <li>Never paste real passwords, OTPs, PINs or card numbers.</li>
              </ul>
            </div>
            <div>
              <h2 className="mb-3 text-base font-semibold">Honest limitations</h2>
              <ul className="list-disc space-y-2 pl-5 text-sm leading-relaxed text-muted">
                <li>Indicators are signals, not proof — legitimate messages can trigger rules.</li>
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
