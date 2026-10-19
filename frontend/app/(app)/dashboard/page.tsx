"use client";

import { useQuery } from "@tanstack/react-query";
import { AlertOctagon, Bell, ClipboardList, FlaskConical, ScanSearch, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

import { EventActivityChart, ScanActivityChart } from "@/components/dashboard/activity-chart";
import { EventRow } from "@/components/events/event-list";
import { PageHeader } from "@/components/page-header";
import { RISK_COLORS, RISK_ORDER, RiskBadge, SourceBadge } from "@/components/risk";
import { ConnectionStatus } from "@/components/shell/connection-status";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, ErrorState, Notice, Skeleton } from "@/components/ui/states";
import { useEventStream, useFallbackInterval } from "@/hooks/use-event-stream";
import { api } from "@/lib/api";
import { cn, formatRelative, humanize } from "@/lib/utils";
import type { SecurityEvent } from "@/types/api";

function Stat({ label, value, icon: Icon, tone }: { label: string; value: number | undefined; icon: typeof Bell; tone?: string }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 py-4">
        <div className={cn("rounded-lg border border-border bg-surface-2 p-2.5", tone)}>
          <Icon className="size-5" aria-hidden />
        </div>
        <div>
          <p className="text-xs text-muted">{label}</p>
          {value === undefined ? (
            <Skeleton className="mt-1 h-7 w-12" />
          ) : (
            <p className="text-2xl font-semibold tabular-nums">{value.toLocaleString()}</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export default function DashboardPage() {
  const refetchInterval = useFallbackInterval();
  const [range, setRange] = useState<"24h" | "7d">("24h");
  const summary = useQuery({ queryKey: ["dashboard", "summary"], queryFn: api.dashboardSummary, refetchInterval });
  const activity = useQuery({
    queryKey: ["dashboard", "activity", range],
    queryFn: () => api.dashboardActivity(range),
    refetchInterval,
  });
  const status = useQuery({ queryKey: ["system-status"], queryFn: api.systemStatus, staleTime: 30_000 });
  const { liveEvents } = useEventStream();

  // Merge live WebSocket events with the persisted list (both come from the database).
  const events = useMemo(() => {
    const merged = new Map<string, SecurityEvent>();
    [...liveEvents, ...(summary.data?.recent_events ?? [])].forEach((e) => merged.set(e.id, e));
    return Array.from(merged.values())
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
      .slice(0, 10);
  }, [liveEvents, summary.data]);
  const liveIds = new Set(liveEvents.map((e) => e.id));

  const s = summary.data;
  const distTotal = s ? RISK_ORDER.reduce((n, l) => n + s.risk_distribution[l], 0) : 0;

  return (
    <>
      <PageHeader
        title="Security dashboard"
        description="Live view of scans, security events and incidents stored by this deployment."
        actions={
          <>
            <Link href="/analyze" className={buttonVariants({ variant: "primary", size: "sm" })}>
              <ScanSearch aria-hidden /> Analyze message
            </Link>
            <Link href="/replay" className={buttonVariants({ variant: "secondary", size: "sm" })}>
              <FlaskConical aria-hidden /> Run demo scenario
            </Link>
          </>
        }
      />

      {summary.isError && <ErrorState error={summary.error} onRetry={() => summary.refetch()} />}
      {s?.demo_records_present && (
        <Notice tone="info" className="mb-5">
          <span className="inline-flex flex-wrap items-center gap-2">
            <SourceBadge source="demo" /> Some figures include synthetic demo/simulation records, labelled throughout.
            Reset them from the Attack replay page.
          </span>
        </Notice>
      )}

      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-5">
        <Stat label="Total scans" value={s?.total_scans} icon={ScanSearch} tone="text-accent" />
        <Stat label="High + critical scans" value={s?.high_risk_scans} icon={ShieldAlert} tone="text-risk-high" />
        <Stat label="Critical scans" value={s?.critical_scans} icon={AlertOctagon} tone="text-rose-400" />
        <Stat label="Open incidents" value={s?.open_incidents} icon={ClipboardList} tone="text-risk-medium" />
        <Stat label="Events (24h)" value={s?.events_24h} icon={Bell} tone="text-muted" />
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader className="flex-row items-center justify-between gap-3">
            <div>
              <CardTitle>Scan activity by risk level</CardTitle>
              <CardDescription>Scans per {range === "24h" ? "hour" : "day"} · stacked by risk level</CardDescription>
            </div>
            <div role="group" aria-label="Time range" className="flex rounded-md border border-border p-0.5">
              {(["24h", "7d"] as const).map((r) => (
                <button
                  key={r}
                  type="button"
                  aria-pressed={range === r}
                  onClick={() => setRange(r)}
                  className={cn(
                    "rounded px-2.5 py-1 text-xs",
                    range === r ? "bg-surface-3 text-fg" : "text-muted hover:text-fg",
                  )}
                >
                  {r}
                </button>
              ))}
            </div>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {activity.data ? (
              <>
                <ScanActivityChart buckets={activity.data.buckets} bucket={activity.data.bucket} />
                <div>
                  <p className="mb-1 text-xs text-muted">Security events per {activity.data.bucket}</p>
                  <EventActivityChart buckets={activity.data.buckets} bucket={activity.data.bucket} />
                </div>
                <details className="text-xs text-muted">
                  <summary className="cursor-pointer select-none">View as table</summary>
                  <div className="mt-2 max-h-56 overflow-auto">
                    <table className="w-full text-left tabular-nums">
                      <thead className="text-subtle">
                        <tr>
                          <th className="py-1 pr-3 font-medium">Bucket start</th>
                          {RISK_ORDER.map((l) => (
                            <th key={l} className="py-1 pr-3 font-medium">{l}</th>
                          ))}
                          <th className="py-1 font-medium">Events</th>
                        </tr>
                      </thead>
                      <tbody>
                        {activity.data.buckets.map((b) => (
                          <tr key={b.start} className="border-t border-border">
                            <td className="py-1 pr-3">{new Date(b.start).toLocaleString()}</td>
                            {RISK_ORDER.map((l) => (
                              <td key={l} className="py-1 pr-3">{b[l]}</td>
                            ))}
                            <td className="py-1">{b.events}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </details>
              </>
            ) : activity.isError ? (
              <ErrorState error={activity.error} onRetry={() => activity.refetch()} />
            ) : (
              <Skeleton className="h-64 w-full" />
            )}
          </CardContent>
        </Card>

        <div className="flex flex-col gap-5">
          <Card>
            <CardHeader>
              <CardTitle>Risk distribution</CardTitle>
              <CardDescription>All stored scans ({distTotal})</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {s ? (
                RISK_ORDER.map((level) => {
                  const count = s.risk_distribution[level];
                  const pct = distTotal ? (count / distTotal) * 100 : 0;
                  return (
                    <div key={level} className="flex flex-col gap-1" title={`${level}: ${count} scans (${pct.toFixed(0)}%)`}>
                      <div className="flex items-center justify-between text-xs">
                        <RiskBadge level={level} />
                        <span className="tabular-nums text-muted">
                          {count} · {pct.toFixed(0)}%
                        </span>
                      </div>
                      <div className="h-2 overflow-hidden rounded-full bg-surface-3" aria-hidden>
                        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: RISK_COLORS[level] }} />
                      </div>
                    </div>
                  );
                })
              ) : (
                <Skeleton className="h-32 w-full" />
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Platform status</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-muted">Event stream</span>
                <ConnectionStatus />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted">Groq LLM</span>
                <Badge tone={status.data?.groq.status === "active" ? "low" : "neutral"}>
                  {status.data ? humanize(status.data.groq.status) : "…"}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted">ML classifier</span>
                <Badge tone={status.data?.classifier.available ? "low" : "neutral"}>
                  {status.data ? (status.data.classifier.available ? "Available" : "Unavailable") : "…"}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted">Database</span>
                <Badge tone={status.data?.database === "ok" ? "low" : "critical"}>{status.data?.database ?? "…"}</Badge>
              </div>
              <Link href="/system-health" className="mt-1 text-accent hover:underline">
                View system health →
              </Link>
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-1">
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>Live event stream</CardTitle>
            <Link href="/events" className="text-xs text-accent hover:underline">All events</Link>
          </CardHeader>
          {events.length === 0 ? (
            <EmptyState title="No events yet" description="High-risk scans and demo scenarios publish events here in real time." />
          ) : (
            <ul aria-live="polite" aria-label="Recent security events">
              {events.map((e) => (
                <EventRow key={e.id} event={e} isNew={liveIds.has(e.id)} />
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>Recent scans</CardTitle>
            <Link href="/history" className="text-xs text-accent hover:underline">History</Link>
          </CardHeader>
          {s && s.recent_scans.length === 0 ? (
            <EmptyState title="No scans yet" action={<Link href="/analyze" className="text-xs text-accent">Analyze a message</Link>} />
          ) : (
            <ul>
              {(s?.recent_scans ?? []).map((scan) => (
                <li key={scan.id} className="border-b border-border last:border-b-0">
                  <Link href={`/history?id=${scan.id}`} className="flex items-start gap-3 px-4 py-3 hover:bg-surface-2">
                    <div className="flex min-w-0 flex-1 flex-col gap-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <RiskBadge level={scan.risk_level} />
                        <span className="text-xs text-muted">{scan.kind === "url" ? "URL" : `Message · ${humanize(scan.content_type)}`}</span>
                        <SourceBadge source={scan.source} />
                      </div>
                      <p className="line-clamp-2 text-xs text-muted">{scan.target_display ?? scan.summary}</p>
                    </div>
                    <span className="text-[11px] whitespace-nowrap text-subtle">{formatRelative(scan.created_at)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>Open incidents</CardTitle>
            <Link href="/incidents" className="text-xs text-accent hover:underline">Incident center</Link>
          </CardHeader>
          {s && s.open_incident_list.length === 0 ? (
            <EmptyState title="No open incidents" />
          ) : (
            <ul>
              {(s?.open_incident_list ?? []).map((inc) => (
                <li key={inc.id} className="border-b border-border last:border-b-0">
                  <Link href={`/incidents?id=${inc.id}`} className="flex flex-col gap-1 px-4 py-3 hover:bg-surface-2">
                    <span className="line-clamp-1 text-sm">{inc.title}</span>
                    <span className="flex flex-wrap items-center gap-2">
                      <RiskBadge level={inc.severity} />
                      <Badge>{humanize(inc.status)}</Badge>
                      <SourceBadge source={inc.source} />
                      <span className="text-[11px] text-subtle">{formatRelative(inc.created_at)}</span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
      {s && <p className="mt-4 text-[11px] text-subtle">{s.provenance_note}</p>}
    </>
  );
}
