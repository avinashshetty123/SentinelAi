import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ScanResultView } from "@/components/scan/scan-result";
import type { ScanResult } from "@/types/api";

vi.mock("next/link", () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

function makeResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    id: "11111111-2222-3333-4444-555555555555",
    kind: "message",
    content_type: "account_verification",
    source: "application",
    created_at: "2026-10-19T10:00:00Z",
    risk_score: 82,
    risk_level: "CRITICAL",
    evidence_strength: "strong",
    summary: "This message matches multiple high-risk scam patterns.",
    ai_summary: null,
    findings: [
      {
        rule_id: "MSG_CREDENTIAL_OTP",
        title: "Request for a one-time code",
        category: "credential_request",
        severity: "high",
        source: "rule",
        weight: 30,
        points: 30,
        explanation: "Asks you to share a one-time code.",
        evidence: "…share the OTP sent to your phone…",
        match_count: 1,
        corroborated_by: [],
      },
      {
        rule_id: "URL_RESERVED_TLD",
        title: "Reserved TLD",
        category: "host",
        severity: "info",
        source: "url_analyzer",
        weight: 0,
        points: 0,
        explanation: "Reserved for documentation.",
        evidence: null,
      },
    ],
    recommendations: ["Do not share one-time codes."],
    limitations: ["Indicators are risk signals, not proof."],
    score_breakdown: [{ category: "credential_request", rule_ids: ["MSG_CREDENTIAL_OTP"], raw: 30, cap: 40, points: 30 }],
    llm: { status: "timeout", model: "openai/gpt-oss-20b", used: false, summary: null, signals_accepted: 0, signals_discarded: 0, latency_ms: 12000 },
    classifier: { status: "available", model_version: "sms-tfidf-lr-1.0", spam_probability: 0.91, points: 11, note: "Baseline" },
    url_details: null,
    extracted_urls: [],
    versions: { rule_version: "msg-rules-1.0", scoring_version: "score-1.0", classifier_version: "sms-tfidf-lr-1.0" },
    privacy: { raw_text_stored: false, excerpts_stored: false, sent_to_llm: true },
    input_length: 120,
    related_event_id: "aaaaaaaa-0000-0000-0000-000000000000",
    related_incident_id: null,
    persisted: true,
    analyzed_text: null,
    highlights: [],
    url_reputations: [],
    ...overrides,
  };
}

describe("ScanResultView", () => {
  it("renders score, label, evidence and recommendations", () => {
    render(<ScanResultView result={makeResult()} />);
    expect(screen.getByRole("img", { name: /risk score 82 out of 100, critical/i })).toBeInTheDocument();
    expect(screen.getAllByText("CRITICAL").length).toBeGreaterThan(0);
    expect(screen.getByText("Request for a one-time code")).toBeInTheDocument();
    expect(screen.getByText(/share the OTP sent to your phone/)).toBeInTheDocument();
    expect(screen.getByText("Do not share one-time codes.")).toBeInTheDocument();
    expect(screen.getByText(/does not mean an 80% chance of fraud/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /security event published/i })).toHaveAttribute(
      "href",
      "/events?id=aaaaaaaa-0000-0000-0000-000000000000",
    );
  });

  it("clearly states when the AI explanation is unavailable (never fakes it)", () => {
    render(<ScanResultView result={makeResult()} />);
    expect(screen.getByText(/provider did not respond in time/i)).toBeInTheDocument();
    expect(screen.queryByText(/^AI explanation$/)).not.toBeInTheDocument();
  });

  it("labels a real AI explanation with provider and model", () => {
    const result = makeResult({
      ai_summary: "The sender pressures you to reveal a code.",
      llm: { status: "ok", model: "openai/gpt-oss-20b", used: true, summary: "x", signals_accepted: 2, signals_discarded: 1, latency_ms: 800 },
    });
    render(<ScanResultView result={result} />);
    expect(screen.getByText("The sender pressures you to reveal a code.")).toBeInTheDocument();
    expect(screen.getByText(/Groq · openai\/gpt-oss-20b/)).toBeInTheDocument();
    expect(screen.getByText(/1 AI claim\(s\) were discarded/)).toBeInTheDocument();
  });

  it("separates informational findings and shows privacy facts", () => {
    render(<ScanResultView result={makeResult()} />);
    expect(screen.getByText(/Informational \(0 points\)/)).toBeInTheDocument();
    expect(screen.getByText("Yes (minimized)")).toBeInTheDocument();
  });

  it("marks demo results", () => {
    render(<ScanResultView result={makeResult({ source: "demo" })} />);
    expect(screen.getByText("Demo")).toBeInTheDocument();
  });
});
