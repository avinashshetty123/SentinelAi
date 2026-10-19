"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Trash2, X } from "lucide-react";
import { Suspense, useState } from "react";

import { PageHeader } from "@/components/page-header";
import { RiskBadge, RiskScore, SourceBadge, SourceIcon } from "@/components/risk";
import { LLM_STATUS_TEXT, ScoreBreakdown } from "@/components/scan/scan-result";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label, Select } from "@/components/ui/form";
import { Pagination } from "@/components/ui/pagination";
import { EmptyState, ErrorState, LoadingState, Notice } from "@/components/ui/states";
import { useSelectedId } from "@/hooks/use-selected-id";
import { api } from "@/lib/api";
import { cn, formatDateTime, formatRelative, humanize } from "@/lib/utils";

const PAGE_SIZE = 15;

function ScanDetailPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const detail = useQuery({ queryKey: ["scans", "detail", id], queryFn: () => api.getScan(id) });
  const remove = useMutation({
    mutationFn: () => api.deleteScan(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      onClose();
    },
  });

  if (detail.isPending) return <LoadingState />;
  if (detail.isError) return <ErrorState error={detail.error} />;
  const scan = detail.data;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start gap-4">
        <RiskScore score={scan.risk_score} level={scan.risk_level} size="sm" />
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <div className="flex flex-wrap gap-2">
            <RiskBadge level={scan.risk_level} />
            <Badge>{humanize(scan.kind)}</Badge>
            <Badge>{humanize(scan.content_type)}</Badge>
            <SourceBadge source={scan.source} />
          </div>
          <p className="text-[11px] text-subtle">
            {scan.id} · {formatDateTime(scan.created_at)}
          </p>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close details">
          <X />
        </Button>
      </div>
      <p className="text-sm leading-relaxed">{scan.summary}</p>
      {scan.target_display && <p className="font-mono text-xs text-muted">Target: {scan.target_display} (path not stored)</p>}
      <Notice>{LLM_STATUS_TEXT[scan.llm_status] ?? scan.llm_status}</Notice>
      <div>
        <h3 className="mb-2 text-xs font-medium text-muted">Findings</h3>
        <ul className="flex flex-col gap-2">
          {scan.findings.filter((f) => f.weight > 0 || f.source === "llm").map((f) => (
            <li key={f.rule_id} className="rounded-md border border-border bg-surface-2 p-3 text-xs">
              <div className="mb-1 flex flex-wrap items-center gap-2">
                <span className="font-medium text-fg">{f.title}</span>
                <SourceIcon source={f.source} />
                <Badge>+{f.points.toFixed(0)}</Badge>
              </div>
              <p className="text-muted">{f.explanation}</p>
              {f.evidence_excerpt && <p className="mt-1 font-mono text-fg/80">{f.evidence_excerpt}</p>}
            </li>
          ))}
        </ul>
      </div>
      <div>
        <h3 className="mb-2 text-xs font-medium text-muted">Score breakdown</h3>
        <ScoreBreakdown breakdown={scan.score_breakdown} score={scan.risk_score} />
      </div>
      <div>
        <h3 className="mb-2 text-xs font-medium text-muted">Recommendations</h3>
        <ul className="list-disc pl-5 text-xs leading-relaxed text-muted">
          {scan.recommendations.map((r) => <li key={r}>{r}</li>)}
        </ul>
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[11px] text-subtle">
        <dt>Rules / scoring</dt>
        <dd className="font-mono">{scan.rule_version} / {scan.scoring_version}</dd>
        <dt>Classifier</dt>
        <dd>{scan.classifier_version ? `${scan.classifier_version} (p=${scan.classifier_probability?.toFixed(3)})` : humanize(scan.classifier_status)}</dd>
        <dt>Sent to LLM</dt>
        <dd>{scan.sent_to_llm ? `Yes${scan.llm_model ? ` (${scan.llm_model})` : ""}` : "No"}</dd>
        <dt>Raw input stored</dt>
        <dd>No — {scan.input_length} characters analyzed in memory</dd>
        <dt>Deleted automatically</dt>
        <dd>{formatDateTime(scan.expires_at)}</dd>
      </dl>
      {confirming ? (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-risk-critical/40 p-3 text-xs">
          <span>Permanently delete this scan record?</span>
          <Button variant="danger" size="sm" loading={remove.isPending} onClick={() => remove.mutate()}>Delete</Button>
          <Button variant="ghost" size="sm" onClick={() => setConfirming(false)}>Cancel</Button>
        </div>
      ) : (
        <Button variant="outline" size="sm" className="self-start" onClick={() => setConfirming(true)}>
          <Trash2 aria-hidden /> Delete record
        </Button>
      )}
      {remove.isError && <ErrorState error={remove.error} />}
    </div>
  );
}

function HistoryView() {
  const [selected, setSelected] = useSelectedId();
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({ kind: "", risk_level: "", source: "" });
  const list = useQuery({
    queryKey: ["scans", "list", page, filters],
    queryFn: () => api.listScans({ page, page_size: PAGE_SIZE, ...filters }),
    placeholderData: (prev) => prev,
  });
  const update = (key: keyof typeof filters, value: string) => {
    setFilters((f) => ({ ...f, [key]: value }));
    setPage(1);
  };

  return (
    <div className="grid gap-5 xl:grid-cols-5">
      <Card className={cn(selected ? "xl:col-span-3" : "xl:col-span-5")}>
        <CardHeader className="gap-3">
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="flex flex-col gap-1">
              <Label htmlFor="f-kind">Type</Label>
              <Select id="f-kind" value={filters.kind} onChange={(e) => update("kind", e.target.value)}>
                <option value="">All</option>
                <option value="message">Message</option>
                <option value="url">URL</option>
              </Select>
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="f-risk">Risk level</Label>
              <Select id="f-risk" value={filters.risk_level} onChange={(e) => update("risk_level", e.target.value)}>
                <option value="">All</option>
                {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((l) => <option key={l} value={l}>{l}</option>)}
              </Select>
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="f-source">Provenance</Label>
              <Select id="f-source" value={filters.source} onChange={(e) => update("source", e.target.value)}>
                <option value="">All</option>
                <option value="application">Application</option>
                <option value="demo">Demo (synthetic)</option>
              </Select>
            </div>
          </div>
        </CardHeader>
        {list.isError ? (
          <CardContent><ErrorState error={list.error} onRetry={() => list.refetch()} /></CardContent>
        ) : list.isPending ? (
          <LoadingState />
        ) : list.data.items.length === 0 ? (
          <EmptyState title="No scans match" description="Scans appear here after you analyze a message or URL." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-sm">
              <caption className="sr-only">Scan history</caption>
              <thead className="text-xs text-muted">
                <tr className="border-b border-border">
                  <th scope="col" className="px-4 py-2 font-medium">Risk</th>
                  <th scope="col" className="px-4 py-2 font-medium">Score</th>
                  <th scope="col" className="px-4 py-2 font-medium">Type</th>
                  <th scope="col" className="px-4 py-2 font-medium">Summary / target</th>
                  <th scope="col" className="px-4 py-2 font-medium">When</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((scan) => (
                  <tr
                    key={scan.id}
                    className={cn("cursor-pointer border-b border-border hover:bg-surface-2", selected === scan.id && "bg-accent/5")}
                    onClick={() => setSelected(scan.id)}
                  >
                    <td className="px-4 py-3"><RiskBadge level={scan.risk_level} /></td>
                    <td className="px-4 py-3 tabular-nums">{scan.risk_score}</td>
                    <td className="px-4 py-3 text-xs text-muted">
                      <div className="flex flex-col gap-1">
                        <span>{scan.kind === "url" ? "URL" : `Message · ${humanize(scan.content_type)}`}</span>
                        <SourceBadge source={scan.source} />
                      </div>
                    </td>
                    <td className="max-w-sm px-4 py-3 text-xs text-muted">
                      <button
                        type="button"
                        className="line-clamp-2 text-left hover:text-fg"
                        onClick={(e) => { e.stopPropagation(); setSelected(scan.id); }}
                        aria-label={`View scan ${scan.id}`}
                      >
                        {scan.target_display ?? scan.summary}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-xs whitespace-nowrap text-subtle">{formatRelative(scan.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {list.data && <Pagination page={page} pageSize={PAGE_SIZE} total={list.data.total} onPageChange={setPage} />}
      </Card>
      {selected && (
        <Card className="xl:col-span-2">
          <CardContent className="py-5">
            <ScanDetailPanel key={selected} id={selected} onClose={() => setSelected(null)} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function HistoryPage() {
  return (
    <>
      <PageHeader
        title="Scan history"
        description="Stored scan metadata: scores, findings and versions. Raw message text is never stored; records are deleted automatically after the retention period."
      />
      <Suspense fallback={<LoadingState />}>
        <HistoryView />
      </Suspense>
      <Card className="mt-5">
        <CardHeader>
          <CardTitle>About retention</CardTitle>
          <CardDescription>
            The server deletes scans after SCAN_RETENTION_DAYS (see Settings). You can delete any record immediately from
            its detail panel.
          </CardDescription>
        </CardHeader>
      </Card>
    </>
  );
}
