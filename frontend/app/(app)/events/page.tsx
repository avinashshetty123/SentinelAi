"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, Search, Square, X, Zap } from "lucide-react";
import Link from "next/link";
import { Suspense, useDeferredValue, useMemo, useState } from "react";

import { EMPTY_FILTERS, matchesFilters, type EventFilterState } from "@/components/events/event-filters";
import { EventRow } from "@/components/events/event-list";
import { PageHeader } from "@/components/page-header";
import { RiskBadge, SourceBadge } from "@/components/risk";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/form";
import { Pagination } from "@/components/ui/pagination";
import { EmptyState, ErrorState, LoadingState, Notice } from "@/components/ui/states";
import { useEventStream, useFallbackInterval } from "@/hooks/use-event-stream";
import { useSelectedId } from "@/hooks/use-selected-id";
import { api, errorMessage } from "@/lib/api";
import { formatDateTime, humanize } from "@/lib/utils";
import type { EventType } from "@/types/api";

const PAGE_SIZE = 20;
const EVENT_TYPES: EventType[] = [
  "high_risk_message",
  "high_risk_url",
  "failed_login_burst",
  "suspicious_login",
  "rate_limit",
  "account_takeover_warning",
  "incident_created",
  "incident_resolved",
];
const SIMULATABLE: EventType[] = ["failed_login_burst", "suspicious_login", "account_takeover_warning", "rate_limit"];

function EventDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const queryClient = useQueryClient();
  const event = useQuery({ queryKey: ["events", "detail", id], queryFn: () => api.getEvent(id) });
  const ack = useMutation({
    mutationFn: () => api.updateEvent(id, "acknowledged"),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["events"] }),
  });
  if (event.isPending) return <LoadingState />;
  if (event.isError) return <ErrorState error={event.error} />;
  const e = event.data;
  return (
    <div className="flex flex-col gap-4 text-sm">
      <div className="flex items-start justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{humanize(e.event_type)}</span>
          <RiskBadge level={e.severity} />
          <SourceBadge source={e.source} />
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close details"><X /></Button>
      </div>
      <p className="leading-relaxed text-muted">{e.description}</p>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs">
        <dt className="text-muted">Event ID</dt><dd className="font-mono break-all">{e.id}</dd>
        <dt className="text-muted">Time</dt><dd>{formatDateTime(e.created_at)}</dd>
        <dt className="text-muted">Actor</dt><dd>{e.actor}</dd>
        <dt className="text-muted">Status</dt><dd>{humanize(e.status)}</dd>
        <dt className="text-muted">Risk score</dt><dd>{e.risk_score ?? "—"}</dd>
        <dt className="text-muted">Source</dt><dd>{e.source === "application" ? "Application activity" : e.source === "demo" ? "Demo scenario (synthetic)" : "Simulation (synthetic)"}</dd>
        <dt className="text-muted">Related scan</dt>
        <dd>{e.scan_id ? <Link className="text-accent hover:underline" href={`/history?id=${e.scan_id}`}>{e.scan_id.slice(0, 8)}</Link> : "—"}</dd>
        <dt className="text-muted">Related incident</dt>
        <dd>{e.incident_id ? <Link className="text-accent hover:underline" href={`/incidents?id=${e.incident_id}`}>{e.incident_id.slice(0, 8)}</Link> : "—"}</dd>
      </dl>
      {e.status === "new" && (
        <Button variant="secondary" size="sm" className="self-start" loading={ack.isPending} onClick={() => ack.mutate()}>
          Acknowledge
        </Button>
      )}
      {!e.incident_id && (
        <Link href={`/incidents?new=1&event=${e.id}`} className="text-xs text-accent hover:underline">
          Open an incident from this event →
        </Link>
      )}
      {ack.isError && <p className="text-xs text-risk-critical">{errorMessage(ack.error)}</p>}
    </div>
  );
}

function DemoControls() {
  const queryClient = useQueryClient();
  const [type, setType] = useState<EventType>("failed_login_burst");
  const simulator = useQuery({ queryKey: ["simulator"], queryFn: api.simulatorStatus, refetchInterval: 10_000 });
  const generate = useMutation({ mutationFn: () => api.simulateEvent(type) });
  const start = useMutation({ mutationFn: () => api.simulatorStart(4), onSuccess: (d) => queryClient.setQueryData(["simulator"], d) });
  const stop = useMutation({ mutationFn: api.simulatorStop, onSuccess: (d) => queryClient.setQueryData(["simulator"], d) });
  const err = generate.error ?? start.error ?? stop.error;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Zap className="size-4 text-violet-300" aria-hidden /> Demo event controls</CardTitle>
        <CardDescription>Generates clearly labelled synthetic events (source: simulation). No real accounts are involved.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-wrap items-end gap-2">
          <div className="flex flex-col gap-1">
            <Label htmlFor="sim-type">Event type</Label>
            <Select id="sim-type" value={type} onChange={(e) => setType(e.target.value as EventType)} className="w-56">
              {SIMULATABLE.map((t) => <option key={t} value={t}>{humanize(t)}</option>)}
            </Select>
          </div>
          <Button variant="secondary" loading={generate.isPending} onClick={() => generate.mutate()}>Generate event</Button>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
          {simulator.data?.running ? (
            <>
              <Badge tone="demo">Simulator running · {simulator.data.events_generated} events</Badge>
              <Button variant="outline" size="sm" loading={stop.isPending} onClick={() => stop.mutate()}><Square aria-hidden /> Stop</Button>
            </>
          ) : (
            <Button variant="outline" size="sm" loading={start.isPending} onClick={() => start.mutate()}><Play aria-hidden /> Start live simulator</Button>
          )}
          <span>Emits one synthetic event every 4s; stops automatically after {simulator.data?.max_seconds ?? 300}s. Only one simulator can run.</span>
        </div>
        {err && <p className="text-xs text-risk-critical">{errorMessage(err)}</p>}
      </CardContent>
    </Card>
  );
}

function EventsView() {
  const [selected, setSelected] = useSelectedId();
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<EventFilterState>(EMPTY_FILTERS);
  const deferredQ = useDeferredValue(filters.q);
  const query = { ...filters, q: deferredQ };
  const refetchInterval = useFallbackInterval();
  const list = useQuery({
    queryKey: ["events", "list", page, query],
    queryFn: () => api.listEvents({ page, page_size: PAGE_SIZE, ...query }),
    placeholderData: (prev) => prev,
    refetchInterval,
  });
  const { liveEvents, status } = useEventStream();
  const freshIds = useMemo(
    () => new Set(liveEvents.filter((e) => matchesFilters(e, query)).map((e) => e.id)),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [liveEvents, query.severity, query.event_type, query.source, query.q],
  );
  const update = <K extends keyof EventFilterState>(key: K, value: EventFilterState[K]) => {
    setFilters((f) => ({ ...f, [key]: value }));
    setPage(1);
  };

  return (
    <div className="flex flex-col gap-5">
      {status !== "open" && (
        <Notice tone="warning">Live stream is not connected; the list refreshes every 15 seconds instead.</Notice>
      )}
      <div className="grid gap-5 xl:grid-cols-5">
        <Card className={selected ? "xl:col-span-3" : "xl:col-span-5"}>
          <CardHeader>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div className="flex flex-col gap-1 lg:col-span-1">
                <Label htmlFor="ev-q">Search</Label>
                <div className="relative">
                  <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-subtle" aria-hidden />
                  <Input id="ev-q" className="pl-9" placeholder="Description or actor" value={filters.q}
                         onChange={(e) => update("q", e.target.value)} maxLength={100} />
                </div>
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="ev-sev">Severity</Label>
                <Select id="ev-sev" value={filters.severity} onChange={(e) => update("severity", e.target.value as EventFilterState["severity"])}>
                  <option value="">All</option>
                  {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((l) => <option key={l} value={l}>{l}</option>)}
                </Select>
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="ev-type">Type</Label>
                <Select id="ev-type" value={filters.event_type} onChange={(e) => update("event_type", e.target.value)}>
                  <option value="">All</option>
                  {EVENT_TYPES.map((t) => <option key={t} value={t}>{humanize(t)}</option>)}
                </Select>
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="ev-src">Provenance</Label>
                <Select id="ev-src" value={filters.source} onChange={(e) => update("source", e.target.value)}>
                  <option value="">All</option>
                  <option value="application">Application</option>
                  <option value="demo">Demo</option>
                  <option value="simulation">Simulation</option>
                </Select>
              </div>
            </div>
          </CardHeader>
          {list.isError ? (
            <CardContent><ErrorState error={list.error} onRetry={() => list.refetch()} /></CardContent>
          ) : list.isPending ? (
            <LoadingState />
          ) : list.data.items.length === 0 ? (
            <EmptyState title="No events match" description="Run a demo scenario or analyze a high-risk message to generate events." />
          ) : (
            <ul aria-live="polite" aria-label="Security events">
              {list.data.items.map((e) => (
                <EventRow key={e.id} event={e} selected={selected === e.id} isNew={freshIds.has(e.id)} onSelect={(ev) => setSelected(ev.id)} />
              ))}
            </ul>
          )}
          {list.data && <Pagination page={page} pageSize={PAGE_SIZE} total={list.data.total} onPageChange={setPage} />}
        </Card>
        {selected && (
          <Card className="xl:col-span-2">
            <CardContent className="py-5">
              <EventDetail key={selected} id={selected} onClose={() => setSelected(null)} />
            </CardContent>
          </Card>
        )}
      </div>
      <DemoControls />
    </div>
  );
}

export default function EventsPage() {
  return (
    <>
      <PageHeader
        title="Security events"
        description="Persisted events from high-risk scans, incidents, rate limiting and labelled simulations, streamed live over WebSocket."
      />
      <Suspense fallback={<LoadingState />}>
        <EventsView />
      </Suspense>
    </>
  );
}
