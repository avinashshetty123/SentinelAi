"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, ClipboardPlus, MessageSquarePlus, Search, Sparkles, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useDeferredValue, useState } from "react";

import { EventRow } from "@/components/events/event-list";
import { CreateIncidentForm } from "@/components/incidents/create-form";
import { IncidentStatusForm, STATUSES } from "@/components/incidents/status-form";
import { PageHeader } from "@/components/page-header";
import { RiskBadge, SourceBadge } from "@/components/risk";
import { Badge, type BadgeTone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FieldError, Input, Label, Select, Textarea } from "@/components/ui/form";
import { Pagination } from "@/components/ui/pagination";
import { EmptyState, ErrorState, LoadingState, Notice } from "@/components/ui/states";
import { useFallbackInterval } from "@/hooks/use-event-stream";
import { useSelectedId } from "@/hooks/use-selected-id";
import { api, errorMessage } from "@/lib/api";
import { cn, formatDateTime, formatRelative } from "@/lib/utils";
import type { IncidentDetail, IncidentStatus } from "@/types/api";

const PAGE_SIZE = 15;
const STATUS_TONE: Record<IncidentStatus, BadgeTone> = {
  OPEN: "high",
  INVESTIGATING: "medium",
  RESOLVED: "low",
  FALSE_POSITIVE: "neutral",
};

function StatusBadge({ status }: { status: IncidentStatus }) {
  return <Badge tone={STATUS_TONE[status]}>{status.replace("_", " ")}</Badge>;
}

function NoteForm({ incidentId }: { incidentId: string }) {
  const queryClient = useQueryClient();
  const [body, setBody] = useState("");
  const [error, setError] = useState<string | null>(null);
  const add = useMutation({
    mutationFn: () => api.addNote(incidentId, body.trim()),
    onSuccess: () => {
      setBody("");
      queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
    },
  });
  return (
    <form
      noValidate
      className="flex flex-col gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (!body.trim()) return setError("Write a note first.");
        if (body.length > 4000) return setError("Notes are limited to 4000 characters.");
        setError(null);
        add.mutate();
      }}
    >
      <Label htmlFor="note-body">Add analyst note</Label>
      <Textarea id="note-body" rows={2} className="min-h-16" value={body} onChange={(e) => setBody(e.target.value)}
                aria-invalid={error ? "true" : "false"} aria-describedby={error ? "note-error" : undefined} />
      <FieldError id="note-error" message={error ?? (add.isError ? errorMessage(add.error) : undefined)} />
      <Button type="submit" size="sm" variant="secondary" className="self-start" loading={add.isPending}>
        <MessageSquarePlus aria-hidden /> Add note
      </Button>
    </form>
  );
}

function IncidentPanel({ incident, onClose }: { incident: IncidentDetail; onClose: () => void }) {
  const queryClient = useQueryClient();
  const update = useMutation({
    mutationFn: (values: Parameters<typeof api.updateIncident>[1]) => api.updateIncident(incident.id, values),
    onSuccess: (data) => {
      queryClient.setQueryData(["incident", incident.id], data);
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
  const ai = useMutation({
    mutationFn: () => api.aiSummary(incident.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["incident", incident.id] }),
  });

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-start gap-2">
        <div className="flex min-w-0 flex-1 flex-col gap-2">
          <h2 className="text-base font-semibold">{incident.title}</h2>
          <div className="flex flex-wrap items-center gap-2">
            <RiskBadge level={incident.severity} />
            <StatusBadge status={incident.status} />
            <SourceBadge source={incident.source} />
            {incident.risk_score !== null && <Badge>score {incident.risk_score}</Badge>}
          </div>
          <p className="text-[11px] text-subtle">
            {incident.id} · opened {formatDateTime(incident.created_at)} by {incident.created_by}
          </p>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close incident"><X /></Button>
      </div>

      {incident.description && <p className="text-sm leading-relaxed text-muted">{incident.description}</p>}
      {incident.evidence_summary && (
        <div>
          <h3 className="mb-1 text-xs font-medium text-muted">Evidence summary</h3>
          <pre className="rounded-md border border-border bg-surface-2 p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap text-fg/90">
            {incident.evidence_summary}
          </pre>
        </div>
      )}
      {incident.scan_id && (
        <Link href={`/history?id=${incident.scan_id}`} className="text-xs text-accent hover:underline">View originating scan →</Link>
      )}

      <Card className="bg-surface-2">
        <CardContent className="py-4">
          <IncidentStatusForm
            key={`${incident.status}-${incident.severity}-${incident.updated_at}`}
            initial={incident}
            pending={update.isPending}
            onSubmit={(v) => update.mutate({
              ...(v.status !== incident.status && { status: v.status }),
              ...(v.severity !== incident.severity && { severity: v.severity }),
              ...(v.resolution_notes.trim() && v.resolution_notes !== (incident.resolution_notes ?? "") && {
                resolution_notes: v.resolution_notes.trim(),
              }),
            })}
          />
          {update.isError && <p className="mt-2 text-xs text-risk-critical">{errorMessage(update.error)}</p>}
        </CardContent>
      </Card>

      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-medium text-muted">AI incident summary</h3>
          <Button variant="outline" size="sm" loading={ai.isPending} onClick={() => ai.mutate()}>
            <Sparkles aria-hidden /> Summarize with Groq
          </Button>
        </div>
        {ai.data && ai.data.status !== "ok" && <Notice tone="warning">{ai.data.message}</Notice>}
        {ai.isError && <Notice tone="danger">{errorMessage(ai.error)}</Notice>}
        <p className="text-[11px] text-subtle">Sends only structured incident metadata (title, severity, evidence summary, event descriptions, notes) — never raw scanned messages.</p>
      </div>

      <div>
        <h3 className="mb-2 text-xs font-medium text-muted">Notes ({incident.notes.length})</h3>
        <ul className="mb-3 flex flex-col gap-2">
          {incident.notes.map((n) => (
            <li key={n.id} className={cn("rounded-md border p-3 text-xs", n.kind === "ai_summary" ? "border-accent/30 bg-accent/5" : "border-border bg-surface-2")}>
              <p className="mb-1 flex items-center gap-2 text-subtle">
                {n.kind === "ai_summary" && <Bot className="size-3.5 text-accent" aria-hidden />}
                <span className="text-fg">{n.author}</span> · {formatRelative(n.created_at)}
                {n.kind === "ai_summary" && <Badge tone="accent">AI-generated</Badge>}
              </p>
              <p className="leading-relaxed whitespace-pre-wrap text-muted">{n.body}</p>
            </li>
          ))}
        </ul>
        <NoteForm incidentId={incident.id} />
      </div>

      <div>
        <h3 className="mb-2 text-xs font-medium text-muted">Linked events ({incident.events.length})</h3>
        {incident.events.length === 0 ? (
          <p className="text-xs text-subtle">No events linked.</p>
        ) : (
          <ul className="rounded-md border border-border">
            {incident.events.map((e) => <EventRow key={e.id} event={e} />)}
          </ul>
        )}
      </div>

      <div>
        <h3 className="mb-2 text-xs font-medium text-muted">Timeline</h3>
        <ol className="relative flex flex-col gap-4 border-l border-border pl-5">
          {incident.timeline.map((t, i) => (
            <li key={`${t.at}-${i}`} className="relative">
              <span aria-hidden className={cn("absolute top-1 -left-[25px] size-2.5 rounded-full border-2 border-surface",
                t.kind === "event" ? "bg-risk-high" : t.kind === "status_change" ? "bg-accent" : t.kind === "ai_summary" ? "bg-violet-400" : "bg-muted")} />
              <p className="text-xs font-medium">{t.title}</p>
              {t.detail && <p className="line-clamp-3 text-xs text-muted">{t.detail}</p>}
              <p className="text-[11px] text-subtle">{formatDateTime(t.at)}{t.actor && ` · ${t.actor}`}</p>
            </li>
          ))}
        </ol>
      </div>

      <details className="text-xs">
        <summary className="cursor-pointer text-muted">Audit trail ({incident.audit.length} records)</summary>
        <table className="mt-2 w-full text-left">
          <thead className="text-subtle"><tr><th className="py-1 font-medium">Time</th><th className="font-medium">Actor</th><th className="font-medium">Action</th><th className="font-medium">Request</th></tr></thead>
          <tbody>
            {incident.audit.map((a) => (
              <tr key={a.id} className="border-t border-border text-muted">
                <td className="py-1 pr-2 whitespace-nowrap">{formatDateTime(a.created_at)}</td>
                <td className="pr-2">{a.actor}</td>
                <td className="pr-2 font-mono">{a.action}</td>
                <td className="font-mono">{a.request_id?.slice(0, 8) ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  );
}

function IncidentDetailLoader({ id, onClose }: { id: string; onClose: () => void }) {
  const detail = useQuery({ queryKey: ["incident", id], queryFn: () => api.getIncident(id) });
  if (detail.isPending) return <LoadingState />;
  if (detail.isError) return <ErrorState error={detail.error} onRetry={() => detail.refetch()} />;
  return <IncidentPanel incident={detail.data} onClose={onClose} />;
}

function IncidentsView() {
  const queryClient = useQueryClient();
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const [selected, setSelected] = useSelectedId();
  const creating = params.get("new") === "1";
  const linkEvent = params.get("event");
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({ status: "", severity: "", q: "" });
  const q = useDeferredValue(filters.q);
  const refetchInterval = useFallbackInterval();
  const list = useQuery({
    queryKey: ["incidents", "list", page, filters.status, filters.severity, q],
    queryFn: () => api.listIncidents({ page, page_size: PAGE_SIZE, status: filters.status, severity: filters.severity, q }),
    placeholderData: (prev) => prev,
    refetchInterval,
  });
  const create = useMutation({
    mutationFn: api.createIncident,
    onSuccess: (incident) => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      router.replace(`${pathname}?id=${incident.id}`, { scroll: false });
    },
  });
  const setCreating = (on: boolean) => router.replace(on ? `${pathname}?new=1` : pathname, { scroll: false });
  const update = (key: keyof typeof filters, value: string) => {
    setFilters((f) => ({ ...f, [key]: value }));
    setPage(1);
  };

  return (
    <div className="flex flex-col gap-5">
      <div className="flex justify-end">
        <Button size="sm" onClick={() => setCreating(true)}><ClipboardPlus aria-hidden /> New incident</Button>
      </div>
      {creating && (
        <Card>
          <CardHeader><CardTitle>New incident</CardTitle></CardHeader>
          <CardContent>
            <CreateIncidentForm
              pending={create.isPending}
              linkedEventId={linkEvent}
              onCancel={() => setCreating(false)}
              onSubmit={(v) => create.mutate({ ...v, event_ids: linkEvent ? [linkEvent] : [] })}
            />
            {create.isError && <p className="mt-2 text-xs text-risk-critical">{errorMessage(create.error)}</p>}
          </CardContent>
        </Card>
      )}
      <div className="grid gap-5 xl:grid-cols-5">
        <Card className={selected ? "xl:col-span-2" : "xl:col-span-5"}>
          <CardHeader>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="flex flex-col gap-1">
                <Label htmlFor="inc-q">Search</Label>
                <div className="relative">
                  <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-subtle" aria-hidden />
                  <Input id="inc-q" className="pl-9" value={filters.q} maxLength={100} onChange={(e) => update("q", e.target.value)} placeholder="Title or description" />
                </div>
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="inc-f-status">Status</Label>
                <Select id="inc-f-status" value={filters.status} onChange={(e) => update("status", e.target.value)}>
                  <option value="">All</option>
                  {STATUSES.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
                </Select>
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="inc-f-sev">Severity</Label>
                <Select id="inc-f-sev" value={filters.severity} onChange={(e) => update("severity", e.target.value)}>
                  <option value="">All</option>
                  {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s} value={s}>{s}</option>)}
                </Select>
              </div>
            </div>
          </CardHeader>
          {list.isError ? (
            <CardContent><ErrorState error={list.error} onRetry={() => list.refetch()} /></CardContent>
          ) : list.isPending ? (
            <LoadingState />
          ) : list.data.items.length === 0 ? (
            <EmptyState title="No incidents" description="Critical scans open incidents automatically; you can also create one manually." />
          ) : (
            <ul>
              {list.data.items.map((inc) => (
                <li key={inc.id} className="border-b border-border last:border-b-0">
                  <button
                    type="button"
                    onClick={() => setSelected(inc.id)}
                    aria-pressed={selected === inc.id}
                    className={cn("flex w-full flex-col gap-1.5 px-4 py-3 text-left hover:bg-surface-2", selected === inc.id && "bg-accent/5")}
                  >
                    <span className="line-clamp-1 text-sm font-medium">{inc.title}</span>
                    <span className="flex flex-wrap items-center gap-2">
                      <RiskBadge level={inc.severity} />
                      <StatusBadge status={inc.status} />
                      <SourceBadge source={inc.source} />
                      <span className="text-[11px] text-subtle">updated {formatRelative(inc.updated_at)}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {list.data && <Pagination page={page} pageSize={PAGE_SIZE} total={list.data.total} onPageChange={setPage} />}
        </Card>
        {selected && (
          <Card className="xl:col-span-3">
            <CardContent className="py-5">
              <IncidentDetailLoader key={selected} id={selected} onClose={() => setSelected(null)} />
            </CardContent>
          </Card>
        )}
      </div>
      <p className="text-[11px] text-subtle">
        Single-operator deployment: all changes are recorded in the audit trail with the request ID. Open and investigating incidents count as open on the dashboard.
      </p>
    </div>
  );
}

export default function IncidentsPage() {
  return (
    <>
      <PageHeader title="Incident center" description="Investigate, annotate and resolve incidents. Every change is audited and appears on the incident timeline." />
      <Suspense fallback={<LoadingState />}>
        <IncidentsView />
      </Suspense>
    </>
  );
}
