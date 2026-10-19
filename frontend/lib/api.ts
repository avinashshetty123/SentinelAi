import { API_URL } from "@/lib/config";
import { getToken } from "@/lib/auth";
import type {
  AuthSession,
  ContentType,
  DashboardActivity,
  DashboardSummary,
  DemoRun,
  EventStatus,
  IncidentDetail,
  IncidentNote,
  IncidentStatus,
  IncidentSummary,
  Page,
  RiskLevel,
  ScanDetail,
  ScanResult,
  ScanSummary,
  Scenario,
  SecurityEvent,
  SimulatorStatus,
  SystemStatus,
} from "@/types/api";

/** Error carrying the backend's consistent error envelope. */
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public requestId: string | null = null,
    public details: unknown = null,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type Query = Record<string, string | number | boolean | null | undefined>;

function buildUrl(path: string, query?: Query): string {
  const url = new URL(`${API_URL}${path}`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

export async function request<T>(
  path: string,
  options: { method?: string; body?: unknown; query?: Query; signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 45_000);
  options.signal?.addEventListener("abort", () => controller.abort());

  let response: Response;
  try {
    response = await fetch(buildUrl(path, options.query), {
      method: options.method ?? "GET",
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
      cache: "no-store",
    });
  } catch (error) {
    const aborted = error instanceof DOMException && error.name === "AbortError";
    throw new ApiError(
      0,
      aborted ? "timeout" : "network_error",
      aborted
        ? "The request timed out. The backend may be starting up — try again shortly."
        : "Cannot reach the SentinelAI API. Check that the backend is running and NEXT_PUBLIC_API_URL is correct.",
    );
  } finally {
    clearTimeout(timer);
  }

  if (response.status === 204) return undefined as T;
  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const err = (payload as { error?: { code?: string; message?: string; request_id?: string; details?: unknown } })
      ?.error;
    throw new ApiError(
      response.status,
      err?.code ?? "http_error",
      err?.message ?? `Request failed with status ${response.status}`,
      err?.request_id ?? response.headers.get("x-request-id"),
      err?.details ?? null,
    );
  }
  return payload as T;
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "Operator token required or invalid. Set it on the Settings page.";
    if (error.status === 429) {
      const retry = (error.details as { retry_after_seconds?: number } | null)?.retry_after_seconds;
      return `Rate limit reached. Try again${retry ? ` in ${retry}s` : " shortly"}.`;
    }
    return error.message;
  }
  return error instanceof Error ? error.message : "Unexpected error";
}

// ---------------------------------------------------------------------------------------------
export const api = {
  authSession: () => request<AuthSession>("/auth/session"),
  systemStatus: () => request<SystemStatus>("/system/status"),
  llmCheck: () =>
    request<{ status: string; model: string | null; latency_ms: number | null; message: string }>("/system/llm-check", {
      method: "POST",
    }),

  scanMessage: (body: { text: string; content_type: ContentType; use_llm: boolean }) =>
    request<ScanResult>("/scans/message", { method: "POST", body }),
  scanUrl: (body: { url: string; use_llm: boolean }) => request<ScanResult>("/scans/url", { method: "POST", body }),
  listScans: (query: { page?: number; page_size?: number; kind?: string; risk_level?: string; source?: string }) =>
    request<Page<ScanSummary>>("/scans", { query }),
  getScan: (id: string) => request<ScanDetail>(`/scans/${id}`),
  deleteScan: (id: string) => request<void>(`/scans/${id}`, { method: "DELETE" }),

  dashboardSummary: () => request<DashboardSummary>("/dashboard/summary"),
  dashboardActivity: (range: "24h" | "7d") => request<DashboardActivity>("/dashboard/activity", { query: { range } }),

  listEvents: (query: {
    page?: number;
    page_size?: number;
    severity?: RiskLevel | "";
    event_type?: string;
    source?: string;
    q?: string;
  }) => request<Page<SecurityEvent>>("/events", { query }),
  getEvent: (id: string) => request<SecurityEvent>(`/events/${id}`),
  updateEvent: (id: string, status: EventStatus) =>
    request<SecurityEvent>(`/events/${id}`, { method: "PATCH", body: { status } }),

  listIncidents: (query: { page?: number; page_size?: number; status?: string; severity?: string; q?: string }) =>
    request<Page<IncidentSummary>>("/incidents", { query }),
  getIncident: (id: string) => request<IncidentDetail>(`/incidents/${id}`),
  createIncident: (body: {
    title: string;
    severity: RiskLevel;
    description?: string;
    evidence_summary?: string;
    risk_score?: number | null;
    scan_id?: string | null;
    event_ids?: string[];
  }) => request<IncidentDetail>("/incidents", { method: "POST", body }),
  updateIncident: (
    id: string,
    body: Partial<{ title: string; description: string; severity: RiskLevel; status: IncidentStatus; resolution_notes: string }>,
  ) => request<IncidentDetail>(`/incidents/${id}`, { method: "PATCH", body }),
  addNote: (id: string, body: string) =>
    request<IncidentNote>(`/incidents/${id}/notes`, { method: "POST", body: { body } }),
  linkEvents: (id: string, eventIds: string[]) =>
    request<IncidentDetail>(`/incidents/${id}/events`, { method: "POST", body: { event_ids: eventIds } }),
  aiSummary: (id: string) =>
    request<{ status: string; model: string | null; note: IncidentNote | null; message: string }>(
      `/incidents/${id}/ai-summary`,
      { method: "POST" },
    ),

  scenarios: () => request<Scenario[]>("/demo/scenarios"),
  runScenario: (id: string) => request<DemoRun>(`/demo/scenarios/${id}/run`, { method: "POST" }),
  scenarioStatus: (id: string) => request<{ scenario_id: string; run: DemoRun | null }>(`/demo/scenarios/${id}/status`),
  cancelRun: (runId: string) => request<{ cancelled: boolean }>(`/demo/runs/${runId}/cancel`, { method: "POST" }),
  simulateEvent: (event_type: string) => request<SecurityEvent>("/demo/events", { method: "POST", body: { event_type } }),
  simulatorStatus: () => request<SimulatorStatus>("/demo/simulator"),
  simulatorStart: (interval_seconds: number) =>
    request<SimulatorStatus>("/demo/simulator/start", { method: "POST", body: { interval_seconds } }),
  simulatorStop: () => request<SimulatorStatus>("/demo/simulator/stop", { method: "POST" }),
  resetDemo: () => request<{ deleted: Record<string, number>; message: string }>("/demo/reset", { method: "POST" }),
};
