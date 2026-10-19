"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { BrainCircuit, Cpu, Database, Globe, Radio, Server, Sparkles } from "lucide-react";
import type { ReactNode } from "react";

import { PageHeader } from "@/components/page-header";
import { ConnectionStatus } from "@/components/shell/connection-status";
import { Badge, type BadgeTone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState, LoadingState, Notice } from "@/components/ui/states";
import { useEventStream } from "@/hooks/use-event-stream";
import { api, errorMessage } from "@/lib/api";
import { API_URL } from "@/lib/config";
import { formatDateTime, humanize } from "@/lib/utils";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-border py-2 text-sm last:border-b-0">
      <span className="text-muted">{label}</span>
      <span className="text-right">{children}</span>
    </div>
  );
}

function Health({ title, icon: Icon, tone, state, children }: { title: string; icon: typeof Server; tone: BadgeTone; state: string; children?: ReactNode }) {
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2"><Icon className="size-4 text-muted" aria-hidden /> {title}</CardTitle>
        <Badge tone={tone}>{state}</Badge>
      </CardHeader>
      {children && <CardContent>{children}</CardContent>}
    </Card>
  );
}

export default function SystemHealthPage() {
  const status = useQuery({ queryKey: ["system-status"], queryFn: api.systemStatus, refetchInterval: 30_000 });
  const ready = useQuery({
    queryKey: ["ready"],
    queryFn: () => fetch(`${API_URL}/health/ready`, { cache: "no-store" }).then(async (r) => ({ ok: r.ok, body: await r.json() })),
    refetchInterval: 30_000,
  });
  const check = useMutation({ mutationFn: api.llmCheck });
  const { status: streamStatus, lastMessageAt } = useEventStream();

  if (status.isPending) return <LoadingState label="Contacting the API…" />;
  if (status.isError)
    return (
      <>
        <PageHeader title="System health" />
        <ErrorState error={status.error} onRetry={() => status.refetch()} />
        <p className="mt-3 text-xs text-muted">API endpoint: <code>{API_URL}</code></p>
      </>
    );
  const s = status.data;
  const metrics = s.classifier.test_metrics as Record<string, number>;

  return (
    <>
      <PageHeader title="System health" description="Service, dependency and provider status. No secrets or internal infrastructure details are exposed." />
      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
        <Health title="FastAPI service" icon={Server} tone="low" state="Running">
          <Row label="Version">{s.version}</Row>
          <Row label="Environment">{s.environment}</Row>
          <Row label="Readiness">{ready.data ? (ready.data.ok ? "Ready" : "Not ready") : "…"}</Row>
          <Row label="Server time">{formatDateTime(s.server_time)}</Row>
        </Health>
        <Health title="Database" icon={Database} tone={s.database === "ok" ? "low" : "critical"} state={s.database === "ok" ? "Connected" : "Unavailable"}>
          <Row label="Engine">PostgreSQL (SQLAlchemy async)</Row>
          <Row label="Scan retention">{String(s.privacy.scan_retention_days)} days</Row>
        </Health>
        <Health title="WebSocket stream" icon={Radio} tone={streamStatus === "open" ? "low" : "medium"} state={humanize(streamStatus)}>
          <Row label="This browser"><ConnectionStatus /></Row>
          <Row label="Connected clients">{s.websocket_clients}</Row>
          <Row label="Last message">{lastMessageAt ? formatDateTime(lastMessageAt) : "—"}</Row>
        </Health>
        <Health title="Groq LLM" icon={Sparkles} tone={s.groq.status === "active" ? "low" : "neutral"} state={humanize(s.groq.status)}>
          <Row label="Model">{s.groq.model ?? "—"}</Row>
          <Row label="Enabled">{s.groq.enabled ? "Yes" : "No"}</Row>
          <Row label="API key configured">{s.groq.configured ? "Yes" : "No"}</Row>
          <div className="mt-3 flex flex-col gap-2">
            <Button variant="secondary" size="sm" className="self-start" loading={check.isPending} onClick={() => check.mutate()}
                    disabled={s.groq.status !== "active"}>
              Run live connectivity check
            </Button>
            {check.data && (
              <Notice tone={check.data.status === "ok" ? "success" : "warning"}>
                {check.data.message}{check.data.latency_ms !== null && ` (${check.data.latency_ms} ms)`}
              </Notice>
            )}
            {check.isError && <Notice tone="danger">{errorMessage(check.error)}</Notice>}
            <p className="text-[11px] text-subtle">Sends one short synthetic message to Groq. The scanner works without Groq.</p>
          </div>
        </Health>
        <Health title="ML classifier" icon={BrainCircuit} tone={s.classifier.available ? "low" : "neutral"} state={s.classifier.available ? "Available" : "Unavailable"}>
          <Row label="Model">{s.classifier.model_version ?? s.classifier.reason ?? "—"}</Row>
          {metrics && "f1_spam" in metrics && (
            <>
              <Row label="Held-out precision / recall">{metrics.precision_spam} / {metrics.recall_spam}</Row>
              <Row label="F1 · false-positive rate">{metrics.f1_spam} · {metrics.false_positive_rate}</Row>
            </>
          )}
          <p className="mt-2 text-[11px] text-subtle">
            Trained on {String(s.classifier.dataset.name ?? "—")} ({String(s.classifier.dataset.license ?? "")}). Measures spam-like
            SMS language, not modern scam coverage. See docs/ML_EVALUATION.md.
          </p>
        </Health>
        <Health title="URL reputation" icon={Globe} tone="neutral" state={humanize(s.reputation.status)}>
          <p className="text-xs text-muted">No reputation provider is configured. URL analysis is offline-only; reputation is reported as unknown.</p>
        </Health>
        <Health title="Security configuration" icon={Cpu} tone={s.auth_mode === "token" ? "low" : "medium"} state={s.auth_mode === "token" ? "Token auth" : "Open (demo)"}>
          <Row label="Rate limiting">{s.rate_limiting ? "Enabled" : "Disabled"}</Row>
          <Row label="Demo mode">{s.demo_mode ? "Enabled" : "Disabled"}</Row>
          <Row label="Thresholds (M/H/C)">{s.thresholds.medium} / {s.thresholds.high} / {s.thresholds.critical}</Row>
          <Row label="Rule / scoring versions"><span className="font-mono text-xs">{s.versions.rules} · {s.versions.scoring}</span></Row>
        </Health>
      </div>
      <p className="mt-4 text-xs text-subtle">API endpoint: <code>{API_URL}</code></p>
    </>
  );
}
