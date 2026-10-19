import { AlertOctagon, AlertTriangle, FlaskConical, Info, ShieldAlert, ShieldCheck } from "lucide-react";

import { Badge, type BadgeTone } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { DataSource, RiskLevel } from "@/types/api";

export const RISK_ORDER: RiskLevel[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export const RISK_COLORS: Record<RiskLevel, string> = {
  LOW: "#16a34a",
  MEDIUM: "#fde047",
  HIGH: "#fb923c",
  CRITICAL: "#e11d48",
};

export function riskTone(level: RiskLevel): BadgeTone {
  return level.toLowerCase() as BadgeTone;
}

const RISK_ICONS = { LOW: ShieldCheck, MEDIUM: Info, HIGH: AlertTriangle, CRITICAL: AlertOctagon } as const;

/** Risk is always shown with BOTH a text label and colour (never colour alone). */
export function RiskBadge({ level, className }: { level: RiskLevel; className?: string }) {
  const Icon = RISK_ICONS[level];
  return (
    <Badge tone={riskTone(level)} className={className}>
      <Icon aria-hidden />
      {level}
    </Badge>
  );
}

export function SourceBadge({ source }: { source: DataSource }) {
  if (source === "application") return null;
  return (
    <Badge tone="demo" title={source === "demo" ? "Synthetic demo scenario data" : "Synthetic simulated event"}>
      <FlaskConical aria-hidden />
      {source === "demo" ? "Demo" : "Simulated"}
    </Badge>
  );
}

export function RiskScore({ score, level, size = "lg" }: { score: number; level: RiskLevel; size?: "sm" | "lg" }) {
  const radius = size === "lg" ? 52 : 26;
  const stroke = size === "lg" ? 10 : 6;
  const circumference = 2 * Math.PI * radius;
  const dimension = (radius + stroke) * 2;
  const offset = circumference * (1 - Math.min(100, Math.max(0, score)) / 100);
  return (
    <div className="relative inline-flex items-center justify-center" role="img"
         aria-label={`Risk score ${score} out of 100, ${level}`}>
      <svg width={dimension} height={dimension} className="-rotate-90">
        <circle cx={dimension / 2} cy={dimension / 2} r={radius} fill="none" stroke="#1a2540" strokeWidth={stroke} />
        <circle
          cx={dimension / 2}
          cy={dimension / 2}
          r={radius}
          fill="none"
          stroke={RISK_COLORS[level]}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-[stroke-dashoffset] duration-700"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={cn("font-semibold tabular-nums", size === "lg" ? "text-3xl" : "text-sm")}>{score}</span>
        {size === "lg" && <span className="text-[10px] uppercase tracking-wider text-muted">of 100</span>}
      </div>
    </div>
  );
}

export function SeverityDot({ level }: { level: RiskLevel }) {
  return <span aria-hidden className="inline-block size-2 shrink-0 rounded-full" style={{ background: RISK_COLORS[level] }} />;
}

export function SourceIcon({ source }: { source: string }) {
  const label = { rule: "Rule", url_analyzer: "URL check", classifier: "ML model", llm: "AI (Groq)", combination: "Combination", reputation: "VirusTotal" }[
    source
  ] ?? source;
  const tone: BadgeTone = source === "llm" ? "accent" : source === "classifier" ? "medium" : source === "reputation" ? "critical" : "neutral";
  return (
    <Badge tone={tone}>
      {source === "llm" ? <ShieldAlert aria-hidden /> : null}
      {label}
    </Badge>
  );
}
