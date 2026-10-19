"use client";

import { useMutation } from "@tanstack/react-query";
import { ArrowDown, CheckCircle2, CircleHelp, Mail, Server, XCircle } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { RiskBadge, RiskScore } from "@/components/risk";
import { FindingItem, ScoreBreakdown } from "@/components/scan/scan-result";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label, Textarea } from "@/components/ui/form";
import { ErrorState, LoadingState, Notice } from "@/components/ui/states";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

const SPOOFED = `Return-Path: <bounce@mailer-x.ru>
Received: from mail.mailer-x.ru (mail.mailer-x.ru [203.0.113.9]) by mx.example.net with ESMTPS
Received: from localhost (unknown [198.51.100.23]) by mail.mailer-x.ru with SMTP
Authentication-Results: mx.example.net; spf=softfail smtp.mailfrom=mailer-x.ru; dkim=none; dmarc=fail (p=REJECT) header.from=paypa1-support.com
From: "PayPal Security" <service@paypa1-support.com>
Reply-To: help@secure-desk.xyz
Subject: Action required: your account has been limited`;

const LEGIT = `Return-Path: <noreply@github.com>
Received: from out-21.smtp.github.com (out-21.smtp.github.com [192.30.252.204]) by mx.example.net with ESMTPS
Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass header.from=github.com
From: GitHub <noreply@github.com>
Subject: [GitHub] A new SSH key was added to your account`;

function AuthPill({ name, value }: { name: string; value: string | undefined }) {
  const ok = value === "pass";
  const bad = value && ["fail", "softfail", "permerror", "invalid"].includes(value);
  const Icon = ok ? CheckCircle2 : bad ? XCircle : CircleHelp;
  return (
    <div className={cn("flex flex-1 flex-col items-center gap-1 rounded-xl border p-4",
      ok ? "border-risk-low/40 bg-risk-low/10" : bad ? "border-risk-critical/40 bg-risk-critical/10" : "border-border bg-surface-2")}>
      <Icon className={cn("size-7", ok ? "text-green-400" : bad ? "text-rose-400" : "text-muted")} aria-hidden />
      <span className="text-xs font-semibold tracking-wider uppercase">{name}</span>
      <span className={cn("text-sm", ok ? "text-green-400" : bad ? "text-rose-400" : "text-muted")}>{value ?? "not recorded"}</span>
    </div>
  );
}

export default function EmailForensicsPage() {
  const [headers, setHeaders] = useState("");
  const scan = useMutation({ mutationFn: api.emailHeaders });
  const r = scan.data;

  return (
    <>
      <PageHeader
        title="E-mail header forensics"
        description="Paste the raw headers of a suspicious e-mail. SentinelAI checks SPF, DKIM and DMARC, spots sender mismatches and lookalike domains, and traces the relay path. Nothing is stored."
      />
      <div className="flex flex-col gap-6">
        <Card>
          <CardContent className="flex flex-col gap-3 py-5">
            <Label htmlFor="hdr">Raw headers</Label>
            <Textarea id="hdr" rows={9} className="font-mono text-xs" value={headers} onChange={(e) => setHeaders(e.target.value)}
                      placeholder="Gmail: ⋮ → Show original · Outlook: File → Properties → Internet headers" />
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-subtle">Synthetic examples:</span>
              <Button variant="outline" size="sm" onClick={() => setHeaders(SPOOFED)}>Spoofed PayPal</Button>
              <Button variant="outline" size="sm" onClick={() => setHeaders(LEGIT)}>Genuine GitHub</Button>
            </div>
            <Button size="lg" className="self-start" loading={scan.isPending} disabled={headers.trim().length < 10}
                    onClick={() => scan.mutate(headers)}>
              <Mail aria-hidden /> Analyze headers
            </Button>
          </CardContent>
        </Card>

        {scan.isPending && <LoadingState label="Reading authentication results and sender identity…" />}
        {scan.isError && <ErrorState error={scan.error} />}
        {r && !scan.isPending && (
          <>
            <Card>
              <CardContent className="flex flex-col gap-5 py-5 sm:flex-row sm:items-center">
                <RiskScore score={r.risk_score} level={r.risk_level} />
                <div className="flex min-w-0 flex-1 flex-col gap-2">
                  <div className="flex flex-wrap gap-2"><RiskBadge level={r.risk_level} /><Badge>{r.evidence_strength} evidence</Badge></div>
                  <p className="text-sm">{r.summary}</p>
                  {r.subject && <p className="text-xs text-muted">Subject: “{r.subject}”</p>}
                </div>
              </CardContent>
            </Card>

            <div className="grid gap-5 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Sender authentication</CardTitle>
                  <CardDescription>As recorded by the receiving mail server.</CardDescription>
                </CardHeader>
                <CardContent className="flex gap-3">
                  <AuthPill name="SPF" value={r.auth.spf} />
                  <AuthPill name="DKIM" value={r.auth.dkim} />
                  <AuthPill name="DMARC" value={r.auth.dmarc} />
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle>Who is really sending this?</CardTitle></CardHeader>
                <CardContent>
                  <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
                    <dt className="text-muted">Displayed as</dt><dd>{r.from_display ?? "—"}</dd>
                    <dt className="text-muted">Real address</dt><dd className="font-mono break-all">{r.from_address ?? "—"}</dd>
                    <dt className="text-muted">Replies go to</dt>
                    <dd className={cn("font-mono", r.reply_to_domain && r.reply_to_domain !== r.from_domain && "text-rose-400")}>{r.reply_to_domain ?? "same as sender"}</dd>
                    <dt className="text-muted">Bounces go to</dt><dd className="font-mono">{r.return_path_domain ?? "—"}</dd>
                  </dl>
                </CardContent>
              </Card>
            </div>

            <div className="grid gap-5 lg:grid-cols-5">
              <Card className="lg:col-span-3">
                <CardHeader><CardTitle>Findings ({r.findings.filter((f) => f.weight > 0).length})</CardTitle></CardHeader>
                <CardContent>
                  <ul className="flex flex-col gap-3">
                    {r.findings.map((f) => <FindingItem key={f.rule_id} finding={f} />)}
                  </ul>
                  {r.findings.length === 0 && <p className="text-sm text-muted">No spoofing indicators found.</p>}
                </CardContent>
              </Card>
              <div className="flex flex-col gap-5 lg:col-span-2">
                {r.hops.length > 0 && (
                  <Card>
                    <CardHeader><CardTitle className="flex items-center gap-2"><Server className="size-4" aria-hidden /> Delivery path</CardTitle></CardHeader>
                    <CardContent>
                      <ol className="flex flex-col items-start gap-1 text-xs">
                        {r.hops.map((h, i) => (
                          <li key={i} className="flex flex-col items-start gap-1">
                            <span className="rounded-md border border-border bg-surface-2 px-2 py-1 font-mono">
                              {h.from ?? "unknown"}{h.ip && <span className="text-subtle"> [{h.ip}]</span>}
                            </span>
                            <ArrowDown className="ml-3 size-3 text-subtle" aria-hidden />
                            {i === r.hops.length - 1 && <span className="rounded-md border border-accent/40 bg-accent/10 px-2 py-1 font-mono">{h.by ?? "recipient"}</span>}
                          </li>
                        ))}
                      </ol>
                    </CardContent>
                  </Card>
                )}
                <Card>
                  <CardHeader><CardTitle>Score breakdown</CardTitle></CardHeader>
                  <CardContent><ScoreBreakdown breakdown={r.score_breakdown} score={r.risk_score} /></CardContent>
                </Card>
                <Card>
                  <CardHeader><CardTitle>What to do</CardTitle></CardHeader>
                  <CardContent>
                    <ul className="list-disc space-y-1.5 pl-5 text-sm">{r.recommendations.map((x) => <li key={x}>{x}</li>)}</ul>
                  </CardContent>
                </Card>
              </div>
            </div>
            <Notice>{r.limitations.join(" ")}</Notice>
          </>
        )}
      </div>
    </>
  );
}
