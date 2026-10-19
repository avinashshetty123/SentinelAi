"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Circle, CircleSlash, FlaskConical, Loader2, Play, RotateCcw, Square, XCircle } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState, LoadingState, Notice } from "@/components/ui/states";
import { useEventStream } from "@/hooks/use-event-stream";
import { api, errorMessage } from "@/lib/api";
import { cn, formatDateTime } from "@/lib/utils";
import type { DemoStep, Scenario } from "@/types/api";

const STEP_ICON = {
  pending: Circle,
  running: Loader2,
  completed: CheckCircle2,
  failed: XCircle,
  skipped: CircleSlash,
} as const;

function StepItem({ step }: { step: DemoStep }) {
  const Icon = STEP_ICON[step.status];
  return (
    <li className="flex gap-3">
      <Icon
        className={cn(
          "mt-0.5 size-4 shrink-0",
          step.status === "completed" && "text-green-400",
          step.status === "running" && "animate-spin text-accent",
          step.status === "failed" && "text-rose-400",
          (step.status === "pending" || step.status === "skipped") && "text-subtle",
        )}
        aria-hidden
      />
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className={cn("text-sm", step.status === "pending" && "text-muted")}>
          {step.title} <span className="sr-only">({step.status})</span>
        </span>
        {step.detail && <span className="text-xs text-muted">{step.detail}</span>}
        <span className="flex flex-wrap gap-3 text-[11px]">
          {step.refs.scan_id && <Link className="text-accent hover:underline" href={`/history?id=${step.refs.scan_id}`}>scan</Link>}
          {step.refs.event_id && <Link className="text-accent hover:underline" href={`/events?id=${step.refs.event_id}`}>event</Link>}
          {step.refs.incident_id && <Link className="text-accent hover:underline" href={`/incidents?id=${step.refs.incident_id}`}>incident</Link>}
        </span>
      </div>
    </li>
  );
}

function ScenarioCard({ scenario }: { scenario: Scenario }) {
  const { status: streamStatus } = useEventStream();
  const statusQuery = useQuery({
    queryKey: ["demo-status", scenario.id],
    queryFn: () => api.scenarioStatus(scenario.id),
    // WebSocket pushes progress; poll only while running and the stream is down.
    refetchInterval: (q) => (q.state.data?.run?.status === "running" && streamStatus !== "open" ? 1500 : false),
  });
  const queryClient = useQueryClient();
  const run = useMutation({
    mutationFn: () => api.runScenario(scenario.id),
    onSuccess: (data) => queryClient.setQueryData(["demo-status", scenario.id], { scenario_id: scenario.id, run: data }),
  });
  const cancel = useMutation({ mutationFn: (id: string) => api.cancelRun(id) });
  const current = statusQuery.data?.run;
  const running = current?.status === "running";
  const incidentId = current?.steps.find((s) => s.refs.incident_id)?.refs.incident_id;

  return (
    <Card className="flex flex-col">
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle>{scenario.title}</CardTitle>
          <Badge tone="demo"><FlaskConical aria-hidden /> Synthetic</Badge>
        </div>
        <CardDescription>{scenario.description}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-4">
        <ol className="flex flex-col gap-3" aria-live="polite">
          {(current?.steps ?? scenario.steps.map((title, index) => ({ index, title, status: "pending" as const, detail: null, refs: {}, at: null }))).map((s) => (
            <StepItem key={s.index} step={s} />
          ))}
        </ol>
        <p className="text-xs text-subtle">Expected: {scenario.expected_outcome}</p>
        {current && (
          <p className="text-xs text-muted">
            Last run: <span className="font-medium text-fg">{current.status}</span> · started {formatDateTime(current.started_at)}
            {current.error && ` · ${current.error}`}
          </p>
        )}
        <div className="mt-auto flex flex-wrap gap-2">
          {running && current ? (
            <Button variant="outline" size="sm" loading={cancel.isPending} onClick={() => cancel.mutate(current.id)}>
              <Square aria-hidden /> Stop
            </Button>
          ) : (
            <Button size="sm" loading={run.isPending} onClick={() => run.mutate()}>
              <Play aria-hidden /> {current ? "Run again" : "Start scenario"}
            </Button>
          )}
          {incidentId && current?.status === "completed" && (
            <Link href={`/incidents?id=${incidentId}`} className="inline-flex items-center text-sm text-accent hover:underline">
              Investigate incident →
            </Link>
          )}
        </div>
        {(run.isError || cancel.isError) && <p className="text-xs text-risk-critical">{errorMessage(run.error ?? cancel.error)}</p>}
      </CardContent>
    </Card>
  );
}

export default function ReplayPage() {
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const queryClient = useQueryClient();
  const [confirm, setConfirm] = useState(false);
  const reset = useMutation({
    mutationFn: api.resetDemo,
    onSuccess: () => {
      setConfirm(false);
      queryClient.invalidateQueries();
    },
  });

  return (
    <>
      <PageHeader
        title="Safe attack replay"
        description="Replay predefined synthetic threat scenarios through the real analysis, event and incident services — watch events stream in and investigate the resulting incident."
      />
      <Notice className="mb-5">
        All scenario content is synthetic. Links use reserved documentation domains (<code>.example</code>) and addresses
        (203.0.113.0/24) and are never visited. Records created here are labelled <strong>demo</strong> and can be reset
        without touching real data.
      </Notice>
      {scenarios.isPending ? (
        <LoadingState />
      ) : scenarios.isError ? (
        <ErrorState error={scenarios.error} onRetry={() => scenarios.refetch()} />
      ) : (
        <div className="grid gap-5 lg:grid-cols-3">
          {scenarios.data.map((s) => <ScenarioCard key={s.id} scenario={s} />)}
        </div>
      )}

      <Card className="mt-6 border-risk-critical/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><RotateCcw className="size-4" aria-hidden /> Reset demo data</CardTitle>
          <CardDescription>
            Deletes only records with demo or simulation provenance (scans, events, incidents, their notes and audit
            records, and run history). Application data is never touched.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          {confirm ? (
            <>
              <span className="text-sm">Delete all demo and simulation records?</span>
              <Button variant="danger" size="sm" loading={reset.isPending} onClick={() => reset.mutate()}>Yes, reset</Button>
              <Button variant="ghost" size="sm" onClick={() => setConfirm(false)}>Cancel</Button>
            </>
          ) : (
            <Button variant="outline" size="sm" onClick={() => setConfirm(true)}>Reset demo data…</Button>
          )}
          {reset.data && (
            <span className="text-xs text-muted">
              Removed: {Object.entries(reset.data.deleted).map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`).join(", ")}
            </span>
          )}
          {reset.isError && <span className="text-xs text-risk-critical">{errorMessage(reset.error)}</span>}
        </CardContent>
      </Card>
    </>
  );
}
