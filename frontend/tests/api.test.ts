import { afterEach, describe, expect, it, vi } from "vitest";

import { matchesFilters, EMPTY_FILTERS } from "@/components/events/event-filters";
import { ApiError, errorMessage, request } from "@/lib/api";
import { setToken } from "@/lib/auth";
import type { SecurityEvent } from "@/types/api";

function mockFetch(impl: (url: string, init: RequestInit) => Promise<Response>) {
  const fn = vi.fn(impl);
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
  setToken(null);
});

describe("API client", () => {
  it("parses the backend error envelope into ApiError", async () => {
    mockFetch(async () =>
      new Response(JSON.stringify({ error: { code: "invalid_url", message: "Only http and https URLs can be analyzed", request_id: "req-123", details: null } }), {
        status: 422,
        headers: { "content-type": "application/json" },
      }),
    );
    const err = await request("/scans/url", { method: "POST", body: { url: "x" } }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 422, code: "invalid_url", requestId: "req-123" });
    expect(errorMessage(err)).toBe("Only http and https URLs can be analyzed");
  });

  it("reports network failures helpfully", async () => {
    mockFetch(async () => {
      throw new TypeError("Failed to fetch");
    });
    const err = await request("/dashboard/summary").catch((e) => e);
    expect(err).toMatchObject({ status: 0, code: "network_error" });
    expect(errorMessage(err)).toMatch(/cannot reach/i);
  });

  it("maps 401 and 429 to actionable messages", () => {
    expect(errorMessage(new ApiError(401, "unauthorized", "x"))).toMatch(/operator token/i);
    expect(errorMessage(new ApiError(429, "rate_limited", "x", null, { retry_after_seconds: 12 }))).toMatch(/12s/);
  });

  it("sends the operator token as a bearer header and JSON body", async () => {
    setToken("tok-abc");
    const fetchMock = mockFetch(async () => new Response(JSON.stringify({ ok: true }), { status: 200 }));
    await request("/incidents", { method: "POST", body: { title: "t" }, query: { page: 2, q: "" } });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8000/api/v1/incidents?page=2");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok-abc");
    expect(init.body).toBe(JSON.stringify({ title: "t" }));
  });

  it("returns undefined for 204", async () => {
    mockFetch(async () => new Response(null, { status: 204 }));
    await expect(request("/scans/x", { method: "DELETE" })).resolves.toBeUndefined();
  });
});

describe("event filtering", () => {
  const event: SecurityEvent = {
    id: "e1",
    created_at: "2026-10-19T10:00:00Z",
    event_type: "suspicious_login",
    severity: "HIGH",
    risk_score: null,
    actor: "synthetic-user-007",
    description: "[SIMULATED] Sign-in from a new device",
    source: "simulation",
    status: "new",
    details: {},
    scan_id: null,
    incident_id: null,
    demo_run_id: null,
  };

  it("matches when no filters are set", () => {
    expect(matchesFilters(event, EMPTY_FILTERS)).toBe(true);
  });

  it("filters by severity, type, source and text", () => {
    expect(matchesFilters(event, { ...EMPTY_FILTERS, severity: "CRITICAL" })).toBe(false);
    expect(matchesFilters(event, { ...EMPTY_FILTERS, severity: "HIGH", event_type: "suspicious_login" })).toBe(true);
    expect(matchesFilters(event, { ...EMPTY_FILTERS, source: "application" })).toBe(false);
    expect(matchesFilters(event, { ...EMPTY_FILTERS, q: "NEW DEVICE" })).toBe(true);
    expect(matchesFilters(event, { ...EMPTY_FILTERS, q: "user-007" })).toBe(true);
    expect(matchesFilters(event, { ...EMPTY_FILTERS, q: "nothing" })).toBe(false);
  });
});
