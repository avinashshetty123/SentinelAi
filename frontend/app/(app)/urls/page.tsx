"use client";

import { useMutation } from "@tanstack/react-query";
import { ShieldOff } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { ScanResultView } from "@/components/scan/scan-result";
import { UrlForm } from "@/components/scan/url-form";
import { Card, CardContent } from "@/components/ui/card";
import { ErrorState, LoadingState, Notice } from "@/components/ui/states";
import { api } from "@/lib/api";

export default function UrlAnalyzerPage() {
  const scan = useMutation({ mutationFn: api.scanUrl });
  return (
    <>
      <PageHeader
        title="URL analyzer"
        description="Inspect a link's structure for phishing techniques — lookalike domains, disguised hosts, encoding tricks and more — without ever opening it."
      />
      <div className="flex flex-col gap-6">
        <Notice>
          <span className="flex items-start gap-2">
            <ShieldOff className="mt-0.5 size-4 shrink-0 text-accent" aria-hidden />
            <span>
              Offline analysis only: SentinelAI never visits, resolves or fetches submitted URLs, and no reputation
              provider is configured, so reputation is reported as unknown. Submitted URLs are never rendered as
              clickable links.
            </span>
          </span>
        </Notice>
        <Card>
          <CardContent className="py-5">
            <UrlForm pending={scan.isPending} onSubmit={(values) => scan.mutate(values)} />
          </CardContent>
        </Card>
        {scan.isPending && <LoadingState label="Analyzing URL structure…" />}
        {scan.isError && <ErrorState error={scan.error} />}
        {scan.data && !scan.isPending && <ScanResultView result={scan.data} />}
      </div>
    </>
  );
}
