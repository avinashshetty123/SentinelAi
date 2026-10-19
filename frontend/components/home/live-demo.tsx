"use client";

import { useMutation } from "@tanstack/react-query";
import { ArrowRight, Loader2, ScanSearch } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { RiskBadge, RiskScore } from "@/components/risk";
import { HighlightedText } from "@/components/scan/visuals";
import { Button } from "@/components/ui/button";
import { api, errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";

const SAMPLES = [
  { label: "Bank KYC scam", text: "URGENT: Your SBI account will be blocked today. Complete KYC at http://sbi-kyc-update.xyz/login and share the OTP sent to your phone. Do not tell anyone." },
  { label: "Job offer", text: "Congratulations! Selected for a part-time job — like YouTube videos and earn Rs 3000 per day. No experience needed. Pay a refundable registration fee of Rs 500. Contact us only on Telegram." },
  { label: "Delivery fee", text: "Your parcel is on hold. Pay the redelivery fee of Rs 25 within 2 hours at bit.ly/dlv-fix or it will be returned." },
  { label: "Normal message", text: "Hey! Your table for 4 at 7:30pm on Friday is confirmed. See you then." },
];

export function LiveDemo() {
  const [active, setActive] = useState(0);
  const [text, setText] = useState(SAMPLES[0].text);
  const scan = useMutation({
    mutationFn: (t: string) => api.scanMessage({ text: t, content_type: "auto", use_llm: false, persist: false }),
  });
  const r = scan.data;

  return (
    <div className="relative rounded-2xl border border-border-strong bg-surface/90 p-5 shadow-2xl shadow-accent/5 backdrop-blur">
      <div className="mb-3 flex items-center justify-between">
        <p className="flex items-center gap-2 text-sm font-semibold">
          <span className="relative flex size-2"><span className="absolute inline-flex size-full animate-ping rounded-full bg-risk-low opacity-75" /><span className="relative inline-flex size-2 rounded-full bg-risk-low" /></span>
          Live engine — try it
        </p>
        <span className="text-[10px] text-subtle">not saved</span>
      </div>
      <div className="mb-3 flex flex-wrap gap-1.5">
        {SAMPLES.map((s, i) => (
          <button key={s.label} type="button"
                  onClick={() => { setActive(i); setText(s.text); scan.reset(); }}
                  className={cn("rounded-full border px-2.5 py-1 text-[11px] transition",
                    active === i ? "border-accent/60 bg-accent/15 text-accent" : "border-border text-muted hover:text-fg")}>
            {s.label}
          </button>
        ))}
      </div>
      {r?.analyzed_text ? (
        <div className="max-h-44 overflow-y-auto"><HighlightedText text={r.analyzed_text} highlights={r.highlights} /></div>
      ) : (
        <textarea
          aria-label="Message to analyze"
          value={text}
          maxLength={2000}
          onChange={(e) => { setText(e.target.value); setActive(-1); }}
          rows={4}
          className="w-full resize-none rounded-lg border border-border bg-bg/60 p-3 font-mono text-xs leading-relaxed text-fg focus-visible:border-accent"
        />
      )}
      <div className="mt-3 flex items-center gap-2">
        {r ? (
          <Button variant="secondary" size="sm" onClick={() => scan.reset()}>Edit text</Button>
        ) : (
          <Button size="sm" disabled={!text.trim() || scan.isPending} onClick={() => scan.mutate(text)}>
            {scan.isPending ? <Loader2 className="animate-spin" aria-hidden /> : <ScanSearch aria-hidden />} Analyze
          </Button>
        )}
        <Link href="/analyze" className="ml-auto inline-flex items-center gap-1 text-xs text-accent hover:underline">
          Full analyzer <ArrowRight className="size-3" aria-hidden />
        </Link>
      </div>
      {scan.isError && <p className="mt-2 text-xs text-risk-critical">{errorMessage(scan.error)}</p>}
      {r && (
        <div className="mt-4 flex items-center gap-4 border-t border-border pt-4" style={{ animation: "var(--animate-fade-up)" }}>
          <RiskScore score={r.risk_score} level={r.risk_level} size="sm" />
          <div className="flex min-w-0 flex-col gap-1">
            <RiskBadge level={r.risk_level} className="self-start" />
            <p className="line-clamp-2 text-xs text-muted">
              {r.findings.filter((f) => f.points > 0).slice(0, 3).map((f) => f.title).join(" · ") || "No risk indicators found."}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
