import * as React from "react";

import { cn } from "@/lib/utils";

const tones = {
  neutral: "border-border-strong bg-surface-3 text-muted",
  accent: "border-accent/40 bg-accent/10 text-accent",
  low: "border-risk-low/40 bg-risk-low/10 text-green-400",
  medium: "border-risk-medium/40 bg-risk-medium/10 text-risk-medium",
  high: "border-risk-high/40 bg-risk-high/10 text-risk-high",
  critical: "border-risk-critical/40 bg-risk-critical/10 text-rose-400",
  demo: "border-violet-400/40 bg-violet-400/10 text-violet-300",
} as const;

export type BadgeTone = keyof typeof tones;

export function Badge({
  tone = "neutral",
  className,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { tone?: BadgeTone }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap [&_svg]:size-3.5",
        tones[tone],
        className,
      )}
      {...props}
    />
  );
}
