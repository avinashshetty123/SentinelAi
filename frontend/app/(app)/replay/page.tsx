"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  Circle,
  CircleSlash,
  Database,
  FileSearch,
  FlaskConical,
  Link2,
  Loader2,
  Play,
  Radio,
  RotateCcw,
  Scale,
  ShieldAlert,
  Sparkles,
  Square,
  XCircle,
} from "lucide-react";
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
  const StatusIcon = STEP_ICON[step.status];
  return (
    <li className="flex gap-3 py-2">
      <StatusIcon
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
          {step.title}
        </span>
        {step.detail && (
          <span className="font-mono text-xs text-muted">{step.detail}</span>
        )}
        <span className="flex flex-wrap gap-3 text-[11px]">
          {step.refs.scan_id && (
            <Link className="text-accent hover:underline" href={`/history?id=${step.refs.scan_id}`}>
              → view scan result
            </Link>
          )}
          {step.refs.event_id && (
            <Link className="text-accent hover:underline" href={`/events?id=${step.refs.event_id}`}>
              → view security event
            </Link>
          )}
          {step.refs.incident_id && (
            <Link className="text-accent hover:underline" href={`/incidents?id=${step.refs.incident_id}`}>
              → investigate incident
            </Link>
          )}
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
    refetchInterval: (q) =>
      q.state.data?.run?.status === "running" && streamStatus !== "open" ? 1500 : false,
  });
  const queryClient = useQueryClient();
  const run = useMutation({
    mutationFn: () => api.runScenario(scenario.id),
    onSuccess: (data) =>
      queryClient.setQueryData(["demo-status", scenario.id], { scenario_id: scenario.id, run: data }),
  });
  const cancel = useMutation({ mutationFn: (id: string) => api.cancelRun(id) });
  const current = statusQuery.data?.run;
  const running = current?.status === "running";
  const incidentId = current?.steps.find((s) => s.refs.incident_id)?.refs.incident_id;
  const completedSteps = current?.steps.filter((s) => s.status === "completed").length ?? 0;
  const totalSteps = current?.steps.length ?? scenario.steps.length;

  return (
    <Card className={cn("flex flex-col transition-colors", running && "border-accent/50")}>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <CardTitle className="text-base">{scenario.title}</CardTitle>
          <div className="flex items-center gap-1.5">
            {running && (
              <Badge tone="neutral" className="animate-pulse border-accent/40 bg-accent/10 text-accent">
                <Radio className="size-3" aria-hidden /> Live
              </Badge>
            )}
            {current?.status === "completed" && <Badge tone="low">Complete</Badge>}
            <Badge tone="demo">
              <FlaskConical className="size-3" aria-hidden /> Demo
            </Badge>
          </div>
        </div>
        <CardDescription className="text-xs leading-relaxed">{scenario.description}</CardDescription>
      </CardHeader>

      <CardContent className="flex flex-1 flex-col gap-4">
        {/* Live progress bar */}
        {running && (
          <div className="flex flex-col gap-1">
            <div className="flex justify-between text-[11px] text-muted">
              <span>Pipeline running…</span>
              <span>{completedSteps} / {totalSteps} steps</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-surface-3">
              <div
                className="h-full rounded-full bg-accent transition-all duration-700"
                style={{ width: `${totalSteps ? (completedSteps / totalSteps) * 100 : 0}%` }}
              />
            </div>
          </div>
        )}

        <ol className="flex flex-col divide-y divide-border" aria-live="polite">
          {(
            current?.steps ??
            scenario.steps.map((title, index) => ({
              index,
              title,
              status: "pending" as const,
              detail: null,
              refs: {},
              at: null,
            }))
          ).map((s) => (
            <StepItem key={s.index} step={s} />
          ))}
        </ol>

        <p className="text-[11px] italic text-subtle">Expected: {scenario.expected_outcome}</p>

        {current && (
          <p className="text-xs text-muted">
            Last run: <span className="font-medium text-fg">{current.status}</span> · started{" "}
            {formatDateTime(current.started_at)}
            {current.error && ` · ${current.error}`}
          </p>
        )}

        <div className="mt-auto flex flex-wrap items-center gap-2">
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
            <Link
              href={`/incidents?id=${incidentId}`}
              className="inline-flex items-center gap-1 text-sm font-medium text-accent hover:underline"
            >
              Investigate incident →
            </Link>
          )}
        </div>
        {(run.isError || cancel.isError) && (
          <p className="text-xs text-risk-critical">{errorMessage(run.error ?? cancel.error)}</p>
        )}
      </CardContent>
    </Card>
  );
}

export default function ReplayPage() {
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const queryClient = useQueryClient();
  const [confirmReset, setConfirmReset] = useState(false);
  const reset = useMutation({
    mutationFn: api.resetDemo,
    onSuccess: () => {
      setConfirmReset(false);
      queryClient.invalidateQueries();
    },
  });

  return (
    <>
      <PageHeader
        title="Attack replay"
        description="Real threat scenarios run through the live detection, scoring, event and incident pipeline. Watch results appear in real time."
      />

      {/* What's real vs what's labelled */}
      <div className="mb-5 grid gap-3 rounded-xl border border-border bg-surface p-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { icon: FileSearch, title: "Real detection engine", sub: "20 rules + ML classifier on every message" },
          { icon: Scale, title: "Real scoring engine", sub: "Deterministic 0–100 score, per-category caps" },
          { icon: Database, title: "Real database records", sub: "Scans, events, incidents persisted to PostgreSQL" },
          { icon: Radio, title: "Real WebSocket broadcast", sub: "Events stream live to the dashboard as they fire" },
        ].map(({ icon: Icon, title, sub }) => (
          <div key={title} className="flex items-start gap-2.5">
            <Icon className="mt-0.5 size-4 shrink-0 text-accent" aria-hidden />
            <div>
              <p className="text-xs font-semibold">{title}</p>
              <p className="text-[11px] text-muted">{sub}</p>
            </div>
          </div>
        ))}
      </div>

      <Notice className="mb-5" tone="info">
        <span className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-xs">
          <FlaskConical className="size-3.5 shrink-0" aria-hidden />
          <strong>What&apos;s labelled synthetic:</strong> the message text and simulated login events
          are crafted inputs — the same kind a real attacker would send. Links use reserved{" "}
          <code>.example</code> domains (RFC 2606) and <code>203.0.113.x</code> addresses (RFC 5737)
          so they can never resolve to real infrastructure. All records are tagged{" "}
          <strong>demo</strong> and can be reset without touching application data.
          <span className="flex items-center gap-1">
            <Sparkles className="size-3" aria-hidden />
            Groq AI explanation runs on the real message text if configured.
          </span>
        </span>
      </Notice>

      {scenarios.isPending ? (
        <LoadingState />
      ) : scenarios.isError ? (
        <ErrorState error={scenarios.error} onRetry={() => scenarios.refetch()} />
      ) : (
        <div className="grid gap-5 lg:grid-cols-3">
          {scenarios.data.map((s) => (
            <ScenarioCard key={s.id} scenario={s} />
          ))}
        </div>
      )}

      <Card className="mt-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <RotateCcw className="size-4" aria-hidden /> Reset demo data
          </CardTitle>
          <CardDescription className="text-xs">
            Deletes only records tagged <strong>demo</strong> or <strong>simulation</strong> — scans,
            events, incidents, notes, audit logs and run history. Application data is never touched.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          {confirmReset ? (
            <>
              <span className="text-sm">Delete all demo and simulation records?</span>
              <Button variant="danger" size="sm" loading={reset.isPending} onClick={() => reset.mutate()}>
                Yes, reset
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setConfirmReset(false)}>
                Cancel
              </Button>
            </>
          ) : (
            <Button variant="outline" size="sm" onClick={() => setConfirmReset(true)}>
              Reset demo data…
            </Button>
          )}
          {reset.data && (
            <span className="text-xs text-muted">
              Removed:{" "}
              {Object.entries(reset.data.deleted)
                .map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`)
                .join(", ")}
            </span>
          )}
          {reset.isError && (
            <span className="text-xs text-risk-critical">{errorMessage(reset.error)}</span>
          )}
        </CardContent>
      </Card>
    </>
  );
}
