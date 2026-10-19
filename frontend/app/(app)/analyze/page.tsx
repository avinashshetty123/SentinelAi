"use client";

import { useMutation, useQuery } from "@tanstack/react-query";

import { PageHeader } from "@/components/page-header";
import { MessageForm } from "@/components/scan/message-form";
import { ScanResultView } from "@/components/scan/scan-result";
import { Card, CardContent } from "@/components/ui/card";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { api } from "@/lib/api";

export default function AnalyzePage() {
  const status = useQuery({ queryKey: ["system-status"], queryFn: api.systemStatus, staleTime: 60_000 });
  const scan = useMutation({ mutationFn: api.scanMessage });

  return (
    <>
      <PageHeader
        title="Message analyzer"
        description="Detect social-engineering indicators in SMS, e-mail, job offers, payment requests and chat messages. Every finding shows its evidence and source."
      />
      <div className="flex flex-col gap-6">
        <Card>
          <CardContent className="py-5">
            <MessageForm
              pending={scan.isPending}
              llmAvailable={status.data ? status.data.groq.status === "active" : null}
              onSubmit={(values) => scan.mutate(values)}
            />
          </CardContent>
        </Card>
        {scan.isPending && <LoadingState label="Running rules, URL checks, classifier and (optional) AI explanation…" />}
        {scan.isError && <ErrorState error={scan.error} />}
        {scan.data && !scan.isPending && <ScanResultView result={scan.data} />}
      </div>
    </>
  );
}
