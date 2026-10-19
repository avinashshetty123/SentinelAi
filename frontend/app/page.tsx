import {
  Activity, ArrowRight, BookOpen, CheckCircle, ClipboardList, FileSearch, GraduationCap, Highlighter, LayoutDashboard,
  Link2, Lock, Mail, PlayCircle, QrCode, ScanLine, ShieldHalf, Sparkles, AlertTriangle,
} from "lucide-react";
import Link from "next/link";

import { LiveDemo } from "@/components/home/live-demo";
import { buttonVariants } from "@/components/ui/button";

const STATS = [
  { value: "20", label: "scam-language rules" },
  { value: "25", label: "offline URL checks" },
  { value: "90+", label: "VirusTotal vendors" },
  { value: "0", label: "raw messages stored" },
];

const FEATURES = [
  { icon: Highlighter, title: "Evidence map", href: "/analyze", text: "Every suspicious phrase highlighted in place, with the rule it triggered. No black-box verdicts." },
  { icon: ScanLine, title: "URL X-ray", href: "/urls", text: "The link taken apart segment by segment — see the fake brand hidden in the subdomain — plus VirusTotal verdicts." },
  { icon: QrCode, title: "QR quishing scanner", href: "/qr", text: "Point your camera at a QR sticker. It's decoded in the browser and the hidden link is checked before you open it." },
  { icon: Mail, title: "E-mail forensics", href: "/email", text: "Paste raw headers: SPF, DKIM, DMARC, reply-to tricks and display-name spoofing, explained." },
  { icon: Activity, title: "Live SOC dashboard", href: "/dashboard", text: "High-risk detections stream in over WebSocket and become incidents with timelines and audit trails." },
  { icon: GraduationCap, title: "Scam Spotter", href: "/lab", text: "An awareness game: guess scam or legit, then see the clues the engine found. Training, not just tooling." },
];

const STEPS = [
  { n: 1, title: "Detect", text: "Deterministic rules, URL heuristics, an ML baseline and VirusTotal each contribute evidence." },
  { n: 2, title: "Score", text: "Capped, deduplicated weights produce a reproducible 0–100 evidence index." },
  { n: 3, title: "Explain", text: "Groq AI writes a plain-English summary — but only claims it can quote survive." },
  { n: 4, title: "Respond", text: "Events, incidents, AI summaries and exportable reports for follow-up." },
];

export default function LandingPage() {
  return (
    <div className="relative min-h-screen overflow-x-hidden">
      {/* Background glow + grid */}
      <div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[720px] bg-[radial-gradient(ellipse_60%_50%_at_50%_0%,rgba(34,211,238,0.14),transparent)]" />
      <div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[720px] opacity-[0.07] [background-image:linear-gradient(#94a3c0_1px,transparent_1px),linear-gradient(90deg,#94a3c0_1px,transparent_1px)] [background-size:44px_44px] [mask-image:linear-gradient(to_bottom,black,transparent)]" />

      <header className="mx-auto flex max-w-6xl items-center justify-between px-4 py-5 sm:px-6">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <ShieldHalf className="size-6 text-accent" aria-hidden />
          <span>Sentinel<span className="text-accent">AI</span></span>
        </Link>
        <nav className="flex items-center gap-1 sm:gap-2">
          <Link href="/how-it-works" className={buttonVariants({ variant: "ghost", size: "sm" })}>How it works</Link>
          <Link href="/dashboard" className={buttonVariants({ variant: "ghost", size: "sm" }) + " hidden sm:inline-flex"}>Dashboard</Link>
          <Link href="/analyze" className={buttonVariants({ size: "sm" })}>Open app <ArrowRight className="size-3.5" aria-hidden /></Link>
        </nav>
      </header>

      <main>
        {/* Hero */}
        <section className="mx-auto grid max-w-6xl items-center gap-10 px-4 pt-10 pb-16 sm:px-6 lg:grid-cols-[1.1fr_1fr] lg:pt-16">
          <div style={{ animation: "var(--animate-fade-up)" }}>
            <p className="mb-5 inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/10 px-3 py-1 text-xs text-accent">
              <Sparkles className="size-3.5" aria-hidden /> AI for Cybersecurity &amp; Digital Safety
            </p>
            <h1 className="text-4xl leading-[1.1] font-semibold tracking-tight sm:text-5xl lg:text-6xl">
              Don&apos;t just ask <span className="text-muted">“is it a scam?”</span>
              <br />
              <span className="bg-gradient-to-r from-accent to-sky-400 bg-clip-text text-transparent">See the proof.</span>
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-muted sm:text-lg">
              SentinelAI checks suspicious messages, links, QR codes and e-mails, highlights the exact words and URL parts that
              give the scam away, scores the risk transparently, and turns real threats into live incidents.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link href="/analyze" className={buttonVariants({ size: "lg" })}><FileSearch aria-hidden /> Analyze a message</Link>
              <Link href="/urls" className={buttonVariants({ variant: "secondary", size: "lg" })}><Link2 aria-hidden /> Check a link</Link>
              <Link href="/replay" className={buttonVariants({ variant: "outline", size: "lg" })}><PlayCircle aria-hidden /> Watch an attack replay</Link>
            </div>
          </div>
          <div style={{ animation: "var(--animate-fade-up)", animationDelay: "0.15s" }}>
            <LiveDemo />
          </div>
        </section>

        {/* Stats */}
        <section className="border-y border-border bg-surface/50">
          <div className="mx-auto grid max-w-6xl grid-cols-2 gap-6 px-4 py-8 sm:px-6 lg:grid-cols-4">
            {STATS.map((s) => (
              <div key={s.label} className="text-center">
                <p className="text-3xl font-semibold text-accent tabular-nums">{s.value}</p>
                <p className="mt-1 text-xs text-muted">{s.label}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Features */}
        <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
          <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">One platform, every way scams reach you</h2>
          <p className="mt-2 max-w-2xl text-sm text-muted">Texts, links, QR stickers and e-mails — analyzed with evidence you can point at.</p>
          <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map(({ icon: Icon, title, text, href }) => (
              <Link key={title} href={href}
                    className="group flex flex-col gap-3 rounded-2xl border border-border bg-surface p-6 transition hover:-translate-y-1 hover:border-accent/40 hover:shadow-lg hover:shadow-accent/5">
                <div className="flex size-10 items-center justify-center rounded-xl border border-accent/20 bg-accent/10">
                  <Icon className="size-5 text-accent" aria-hidden />
                </div>
                <h3 className="font-semibold group-hover:text-accent">{title}</h3>
                <p className="text-sm leading-relaxed text-muted">{text}</p>
                <span className="mt-auto inline-flex items-center gap-1 text-xs text-accent opacity-0 transition group-hover:opacity-100">Open <ArrowRight className="size-3" aria-hidden /></span>
              </Link>
            ))}
          </div>
        </section>

        {/* How it works */}
        <section className="border-t border-border bg-surface/40">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
            <div className="flex flex-wrap items-end justify-between gap-4">
              <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">AI that has to show its work</h2>
              <Link href="/how-it-works" className={buttonVariants({ variant: "outline", size: "sm" })}><BookOpen aria-hidden /> Full explanation</Link>
            </div>
            <ol className="mt-8 grid gap-4 md:grid-cols-4">
              {STEPS.map((s) => (
                <li key={s.n} className="rounded-2xl border border-border bg-surface p-5">
                  <span className="flex size-8 items-center justify-center rounded-full bg-accent/15 text-sm font-bold text-accent">{s.n}</span>
                  <p className="mt-3 font-semibold">{s.title}</p>
                  <p className="mt-1 text-sm leading-relaxed text-muted">{s.text}</p>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* Trust */}
        <section className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
          <div className="grid gap-6 rounded-2xl border border-border bg-surface p-6 md:grid-cols-2 md:p-8">
            <div>
              <h2 className="mb-3 flex items-center gap-2 font-semibold"><Lock className="size-4 text-accent" aria-hidden /> Private by design</h2>
              <ul className="space-y-2 text-sm text-muted">
                {["Messages are analyzed in memory — never stored.", "Numbers and e-mails are masked before anything reaches the AI.",
                  "Links are never opened; VirusTotal is queried by URL ID.", "QR images are decoded in your browser."].map((t) => (
                  <li key={t} className="flex gap-2"><CheckCircle className="mt-0.5 size-4 shrink-0 text-green-400" aria-hidden />{t}</li>
                ))}
              </ul>
            </div>
            <div>
              <h2 className="mb-3 flex items-center gap-2 font-semibold"><AlertTriangle className="size-4 text-risk-medium" aria-hidden /> Honest about limits</h2>
              <ul className="space-y-2 text-sm text-muted">
                {["The score is an evidence index, not a probability of fraud.", "Brand-new phishing links may not be on VirusTotal yet.",
                  "The ML model was trained on English SMS spam.", "Login events in attack replays are simulated and labelled."].map((t) => (
                  <li key={t} className="flex gap-2"><span className="mt-2 size-1.5 shrink-0 rounded-full bg-risk-medium" />{t}</li>
                ))}
              </ul>
            </div>
          </div>
          <div className="mt-10 flex flex-wrap justify-center gap-3">
            <Link href="/dashboard" className={buttonVariants({ size: "lg" })}><LayoutDashboard aria-hidden /> Open the dashboard</Link>
            <Link href="/incidents" className={buttonVariants({ variant: "secondary", size: "lg" })}><ClipboardList aria-hidden /> Incident center</Link>
          </div>
        </section>
      </main>

      <footer className="border-t border-border py-6 text-center text-xs text-subtle">
        SentinelAI · hackathon prototype · not a substitute for professional security advice
      </footer>
    </div>
  );
}
