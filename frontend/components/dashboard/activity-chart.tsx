"use client";

import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { RISK_COLORS, RISK_ORDER } from "@/components/risk";
import type { ActivityBucket } from "@/types/api";

const SURFACE = "#0f172a";
const AXIS = { stroke: "#64748b", fontSize: 11 };

function label(start: string, bucket: "hour" | "day") {
  const d = new Date(start);
  return bucket === "hour"
    ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

interface TooltipEntry {
  name?: string;
  value?: number;
  color?: string;
}

function ChartTooltip({ active, payload, label: l }: { active?: boolean; payload?: TooltipEntry[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-md border border-border bg-surface-2 px-3 py-2 text-xs shadow-lg">
      <p className="mb-1 font-medium text-fg">{l}</p>
      {payload.map((p) => (
        <p key={p.name} className="flex items-center gap-2 text-muted">
          <span className="inline-block size-2 rounded-sm" style={{ background: p.color }} aria-hidden />
          {p.name}: <span className="tabular-nums text-fg">{p.value}</span>
        </p>
      ))}
    </div>
  );
}

/** Scans per time bucket, stacked by risk level (single y-axis, counts). */
export function ScanActivityChart({ buckets, bucket }: { buckets: ActivityBucket[]; bucket: "hour" | "day" }) {
  const data = buckets.map((b) => ({ ...b, label: label(b.start, bucket) }));
  return (
    <div className="h-64 w-full" role="img" aria-label="Stacked bar chart of scans over time by risk level">
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
          <CartesianGrid stroke="#1a2540" vertical={false} />
          <XAxis dataKey="label" tick={AXIS} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={16} />
          <YAxis allowDecimals={false} tick={AXIS} tickLine={false} axisLine={false} />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(148,163,192,0.08)" }} />
          <Legend iconType="square" iconSize={8} wrapperStyle={{ fontSize: 11, color: "#94a3c0" }} />
          {RISK_ORDER.map((level, i) => (
            <Bar
              key={level}
              dataKey={level}
              name={level}
              stackId="risk"
              fill={RISK_COLORS[level]}
              stroke={SURFACE}
              strokeWidth={1}
              radius={i === RISK_ORDER.length - 1 ? [3, 3, 0, 0] : 0}
              maxBarSize={22}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Security events per bucket: a separate single-series chart (never a second axis on the scan chart). */
export function EventActivityChart({ buckets, bucket }: { buckets: ActivityBucket[]; bucket: "hour" | "day" }) {
  const data = buckets.map((b) => ({ events: b.events, label: label(b.start, bucket) }));
  return (
    <div className="h-36 w-full" role="img" aria-label="Bar chart of security events over time">
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
          <CartesianGrid stroke="#1a2540" vertical={false} />
          <XAxis dataKey="label" tick={AXIS} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={16} />
          <YAxis allowDecimals={false} tick={AXIS} tickLine={false} axisLine={false} />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(148,163,192,0.08)" }} />
          <Bar dataKey="events" name="Events" fill="#22d3ee" radius={[3, 3, 0, 0]} maxBarSize={22} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
