"use client";

import { Radio, RefreshCw, WifiOff } from "lucide-react";

import { useEventStream } from "@/hooks/use-event-stream";
import { cn } from "@/lib/utils";

const LABELS = {
  connecting: "Connecting…",
  open: "Live",
  reconnecting: "Reconnecting…",
  unauthorized: "Token required",
  offline: "Offline · polling",
} as const;

export function ConnectionStatus({ compact = false }: { compact?: boolean }) {
  const { status, reconnect } = useEventStream();
  const tone =
    status === "open"
      ? "text-risk-low border-risk-low/40 bg-risk-low/10"
      : status === "unauthorized" || status === "offline"
        ? "text-risk-critical border-risk-critical/40 bg-risk-critical/10"
        : "text-risk-medium border-risk-medium/40 bg-risk-medium/10";
  const Icon = status === "open" ? Radio : status === "offline" || status === "unauthorized" ? WifiOff : RefreshCw;
  return (
    <button
      type="button"
      onClick={reconnect}
      title="Real-time event stream status (click to reconnect)"
      aria-label={`Event stream: ${LABELS[status]}. Click to reconnect.`}
      className={cn("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium", tone)}
    >
      <Icon className={cn("size-3.5", status === "reconnecting" || status === "connecting" ? "animate-spin" : "")} aria-hidden />
      {!compact && LABELS[status]}
    </button>
  );
}
