"use client";

import { ExternalLink, ShieldAlert, ShieldCheck, ShieldQuestion, ShieldX } from "lucide-react";
import { useState } from "react";
import { PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer, Tooltip } from "recharts";

import { Badge } from "@/components/ui/badge";
import { cn, formatDateTime, humanize } from "@/lib/utils";
import type { Finding, Highlight, ReputationInfo, ScoreCategory, UrlPart } from "@/types/api";

// ---------------------------------------------------------------------------------------------
// Evidence map: the analyzed message with every triggering phrase highlighted in place.
// ---------------------------------------------------------------------------------------------
const SOURCE_STYLE: Record<string, string> = {
  rule: "bg-rose-500/20 decoration-rose-400",
  url_analyzer: "bg-orange-400/20 decoration-orange-300",
  reputation: "bg-red-600/25 decoration-red-400",
  llm: "bg-cyan-400/15 decoration-cyan-300",
};

export function HighlightedText({ text, highlights }: { text: string; highlights: Highlight[] }) {
  const [active, setActive] = useState<string | null>(null);
  // Flatten overlapping spans into segments; each segment lists every finding covering it.
  const bounds = new Set<number>([0, text.length]);
  highlights.forEach((h) => {
    bounds.add(h.start);
    bounds.add(h.end);
  });
  const points = Array.from(bounds).sort((a, b) => a - b);
  const segments = points.slice(0, -1).map((start, i) => {
    const end = points[i + 1];
    return { start, end, covers: highlights.filter((h) => h.start <= start && h.end >= end) };
  });
  const legend = Array.from(new Map(highlights.map((h) => [h.rule_id, h])).values());

  return (
    <div className="flex flex-col gap-3">
      <p className="rounded-lg border border-border bg-bg/60 p-4 font-mono text-sm leading-7 whitespace-pre-wrap break-words">
        {segments.map((seg) => {
          const piece = text.slice(seg.start, seg.end);
          if (seg.covers.length === 0) return <span key={seg.start}>{piece}</span>;
          const top = seg.covers[0];
          const dim = active !== null && !seg.covers.some((c) => c.rule_id === active);
          return (
            <mark
              key={seg.start}
              title={seg.covers.map((c) => `${c.title} (${humanize(c.source)})`).join("\n")}
              className={cn(
                "rounded-sm px-0.5 text-fg underline decoration-2 underline-offset-4 transition-opacity",
                SOURCE_STYLE[top.source] ?? SOURCE_STYLE.rule,
                dim && "opacity-30",
              )}
            >
              {piece}
            </mark>
          );
        })}
      </p>
      {legend.length > 0 && (
        <div className="flex flex-wrap gap-1.5" aria-label="Highlighted indicators">
          {legend.map((h) => (
            <button
              key={h.rule_id}
              type="button"
              onMouseEnter={() => setActive(h.rule_id)}
              onMouseLeave={() => setActive(null)}
              onFocus={() => setActive(h.rule_id)}
              onBlur={() => setActive(null)}
              className={cn(
                "rounded-md border border-border px-2 py-0.5 text-[11px] text-muted hover:text-fg",
                SOURCE_STYLE[h.source] ?? SOURCE_STYLE.rule,
              )}
            >
              {h.title}
            </button>
          ))}
        </div>
      )}
      <p className="text-[11px] text-subtle">
        Hover an indicator to focus its evidence. Red = rule, orange = link check, cyan = AI-identified. This text is
        shown back to you once and is not stored.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// URL X-ray: the address split into its parts, with the parts attackers abused lit up.
// ---------------------------------------------------------------------------------------------
const PART_LABEL: Record<UrlPart["label"], string> = {
  scheme: "Protocol",
  userinfo: "User-info (ignored by browser)",
  subdomain: "Subdomain",
  domain: "Real domain",
  suffix: "TLD",
  host: "Host",
  port: "Port",
  path: "Path",
  query: "Query",
  fragment: "Fragment",
};

export function UrlXray({ parts, findings }: { parts: UrlPart[]; findings: Finding[] }) {
  const titles = new Map(findings.map((f) => [f.rule_id, f.title]));
  return (
    <div className="flex flex-col gap-4">
      <div className="overflow-x-auto pb-2">
        <div className="flex min-w-max items-stretch gap-1 font-mono text-sm">
          {parts.map((p, i) => {
            const flagged = p.flags.some((f) => (titles.get(f) ?? "") && !f.startsWith("URL_OFFICIAL"));
            const official = p.flags.includes("URL_OFFICIAL_DOMAIN");
            return (
              <div key={i} className="flex flex-col items-center gap-1">
                <span
                  className={cn(
                    "rounded-md border px-2 py-1.5 whitespace-nowrap",
                    flagged
                      ? "border-risk-critical/60 bg-risk-critical/15 text-rose-300"
                      : official
                        ? "border-risk-low/50 bg-risk-low/10 text-green-300"
                        : p.label === "domain"
                          ? "border-accent/50 bg-accent/10 text-fg"
                          : "border-border bg-surface-2 text-muted",
                  )}
                >
                  {p.value.length > 48 ? `${p.value.slice(0, 46)}…` : p.value}
                </span>
                <span className={cn("text-[10px] uppercase tracking-wide", flagged ? "text-rose-300" : "text-subtle")}>
                  {PART_LABEL[p.label]}
                </span>
              </div>
            );
          })}
        </div>
      </div>
      <ul className="grid gap-2 sm:grid-cols-2">
        {parts
          .filter((p) => p.flags.length)
          .flatMap((p) =>
            p.flags.map((f) => (
              <li key={`${p.label}-${f}`} className="flex items-start gap-2 rounded-md border border-border bg-surface-2 px-3 py-2 text-xs">
                <Badge tone={f === "URL_OFFICIAL_DOMAIN" ? "low" : "critical"} className="shrink-0">
                  {PART_LABEL[p.label].split(" ")[0]}
                </Badge>
                <span className="text-muted">{titles.get(f) ?? humanize(f.replace(/^URL_/, ""))}</span>
              </li>
            )),
          )}
      </ul>
      <p className="text-[11px] text-subtle">
        Browsers trust the <span className="text-accent">real domain</span> (just before the TLD) — everything to its
        left can be chosen freely by an attacker.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// VirusTotal reputation card.
// ---------------------------------------------------------------------------------------------
const VERDICT = {
  malicious: { icon: ShieldX, label: "Malicious", tone: "critical" as const, color: "text-rose-400" },
  suspicious: { icon: ShieldAlert, label: "Suspicious", tone: "high" as const, color: "text-risk-high" },
  clean: { icon: ShieldCheck, label: "No detections", tone: "low" as const, color: "text-green-400" },
  not_found: { icon: ShieldQuestion, label: "Never seen", tone: "neutral" as const, color: "text-muted" },
  unknown: { icon: ShieldQuestion, label: "Unknown", tone: "neutral" as const, color: "text-muted" },
};

export function ReputationCard({ reputation, compact = false }: { reputation: ReputationInfo; compact?: boolean }) {
  const v = VERDICT[reputation.verdict] ?? VERDICT.unknown;
  const Icon = v.icon;
  const s = reputation.stats;
  const total = s ? s.malicious + s.suspicious + s.harmless + s.undetected + s.timeout : 0;
  const seg = (n: number) => (total ? `${(n / total) * 100}%` : "0%");

  if (reputation.status !== "ok") {
    return (
      <div className="flex items-start gap-3 text-xs text-muted">
        <ShieldQuestion className="mt-0.5 size-5 shrink-0" aria-hidden />
        <div>
          <p className="font-medium text-fg">
            {reputation.status === "not_configured" ? "Reputation not configured" : `VirusTotal ${humanize(reputation.status)}`}
          </p>
          <p>{reputation.note}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-3">
        <Icon className={cn("size-9 shrink-0", v.color)} aria-hidden />
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn("text-lg font-semibold", v.color)}>{v.label}</span>
            {s && total > 0 && (
              <span className="text-sm tabular-nums text-muted">
                {s.malicious + s.suspicious}/{total} vendors flagged
              </span>
            )}
            {reputation.cached && <Badge>cached</Badge>}
          </div>
          <p className="text-xs text-muted">{reputation.note}</p>
        </div>
      </div>
      {s && total > 0 && (
        <div>
          <div className="flex h-2.5 overflow-hidden rounded-full bg-surface-3" role="img"
               aria-label={`${s.malicious} malicious, ${s.suspicious} suspicious, ${s.harmless} harmless, ${s.undetected} undetected`}>
            <div className="bg-risk-critical" style={{ width: seg(s.malicious) }} />
            <div className="bg-risk-high" style={{ width: seg(s.suspicious) }} />
            <div className="bg-risk-low" style={{ width: seg(s.harmless) }} />
            <div className="bg-subtle/50" style={{ width: seg(s.undetected + s.timeout) }} />
          </div>
          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted tabular-nums">
            <span><span className="text-rose-400">■</span> {s.malicious} malicious</span>
            <span><span className="text-risk-high">■</span> {s.suspicious} suspicious</span>
            <span><span className="text-green-400">■</span> {s.harmless} harmless</span>
            <span><span className="text-subtle">■</span> {s.undetected} undetected</span>
          </div>
        </div>
      )}
      {!compact && reputation.flagged_engines.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {reputation.flagged_engines.map((e) => (
            <Badge key={e.engine} tone={e.category === "malicious" ? "critical" : "high"} title={e.result ?? e.category}>
              {e.engine}
              {e.result ? ` · ${e.result}` : ""}
            </Badge>
          ))}
        </div>
      )}
      {!compact && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-subtle">
          {reputation.categories.length > 0 && <span>Categories: {reputation.categories.join(", ")}</span>}
          {reputation.community_score !== null && <span>Community score: {reputation.community_score}</span>}
          {reputation.last_analysis_at && <span>Last analysed {formatDateTime(reputation.last_analysis_at)}</span>}
          {reputation.report_url && (
            <a href={reputation.report_url} target="_blank" rel="noopener noreferrer"
               className="inline-flex items-center gap-1 text-accent hover:underline">
              Full VirusTotal report <ExternalLink className="size-3" aria-hidden />
            </a>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Threat fingerprint: how much of each cap every evidence category used.
// ---------------------------------------------------------------------------------------------
export function ThreatFingerprint({ breakdown }: { breakdown: ScoreCategory[] }) {
  const rows = breakdown.filter((b) => b.cap > 0 && b.category !== "combination");
  if (rows.length < 3) return null;
  const data = rows.map((b) => ({ axis: humanize(b.category), value: Math.round((b.points / b.cap) * 100) }));
  return (
    <div className="h-60 w-full" role="img" aria-label="Radar chart of evidence per category as a share of its cap">
      <ResponsiveContainer>
        <RadarChart data={data} outerRadius="72%">
          <PolarGrid stroke="#22304d" />
          <PolarAngleAxis dataKey="axis" tick={{ fill: "#94a3c0", fontSize: 10 }} />
          <Tooltip
            formatter={(v) => [`${v}% of category cap`, "Evidence"]}
            contentStyle={{ background: "#131d33", border: "1px solid #22304d", borderRadius: 8, fontSize: 12 }}
          />
          <Radar dataKey="value" stroke="#22d3ee" fill="#22d3ee" fillOpacity={0.25} strokeWidth={2} />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  );
}
