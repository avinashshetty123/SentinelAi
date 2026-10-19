// Mirrors the FastAPI response models (backend/app/schemas). Keep in sync with /openapi.json.

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type DataSource = "application" | "demo" | "simulation";
export type ScanKind = "message" | "url";
export type ContentType =
  | "auto"
  | "sms"
  | "email"
  | "job_offer"
  | "payment_request"
  | "account_verification"
  | "delivery"
  | "prize"
  | "chat"
  | "general";
export type IncidentStatus = "OPEN" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE";
export type EventType =
  | "high_risk_message"
  | "high_risk_url"
  | "failed_login_burst"
  | "suspicious_login"
  | "rate_limit"
  | "account_takeover_warning"
  | "incident_created"
  | "incident_resolved";
export type EventStatus = "new" | "acknowledged" | "linked";

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface Finding {
  rule_id: string;
  title: string;
  category: string;
  severity: string;
  source: string;
  weight: number;
  points: number;
  explanation: string;
  evidence?: string | null;
  match_count?: number;
  corroborated_by?: string[];
}

export interface StoredFinding {
  rule_id: string;
  title: string;
  category: string;
  severity: string;
  source: string;
  weight: number;
  points: number;
  explanation: string;
  evidence_excerpt: string | null;
}

export interface ScoreCategory {
  category: string;
  rule_ids: string[];
  raw: number;
  cap: number;
  points: number;
}

export interface LLMInfo {
  status: string;
  model: string | null;
  used: boolean;
  summary: string | null;
  signals_accepted: number;
  signals_discarded: number;
  latency_ms: number | null;
}

export interface ClassifierInfo {
  status: "available" | "unavailable" | "disabled" | "not_applicable";
  model_version: string | null;
  spam_probability: number | null;
  points: number;
  note: string | null;
}

export interface ReputationInfo {
  status: "not_configured" | "unavailable" | "ok";
  provider: string | null;
  note: string;
}

export interface UrlDetails {
  normalized_url: string;
  display_target: string;
  scheme: string;
  scheme_assumed: boolean;
  host: string;
  host_unicode: string;
  registered_domain: string | null;
  subdomain: string;
  port: number | null;
  is_ip: boolean;
  is_official_brand_domain: boolean;
  reputation: ReputationInfo;
}

export interface ScanResult {
  id: string;
  kind: ScanKind;
  content_type: string;
  source: DataSource;
  created_at: string;
  risk_score: number;
  risk_level: RiskLevel;
  evidence_strength: string;
  summary: string;
  ai_summary: string | null;
  findings: Finding[];
  recommendations: string[];
  limitations: string[];
  score_breakdown: ScoreCategory[];
  llm: LLMInfo;
  classifier: ClassifierInfo;
  url_details: UrlDetails | null;
  extracted_urls: string[];
  versions: { rule_version: string; scoring_version: string; classifier_version: string | null };
  privacy: { raw_text_stored: boolean; excerpts_stored: boolean; sent_to_llm: boolean };
  input_length: number;
  related_event_id: string | null;
  related_incident_id: string | null;
}

export interface ScanSummary {
  id: string;
  kind: ScanKind;
  content_type: string;
  source: DataSource;
  created_at: string;
  risk_score: number;
  risk_level: RiskLevel;
  evidence_strength: string;
  summary: string;
  target_display: string | null;
  llm_status: string;
  url_count: number;
}

export interface ScanDetail extends ScanSummary {
  ai_summary: string | null;
  recommendations: string[];
  limitations: string[];
  score_breakdown: ScoreCategory[];
  llm_model: string | null;
  sent_to_llm: boolean;
  classifier_status: string;
  classifier_version: string | null;
  classifier_probability: number | null;
  rule_version: string;
  scoring_version: string;
  input_length: number;
  expires_at: string;
  findings: StoredFinding[];
}

export interface SecurityEvent {
  id: string;
  created_at: string;
  event_type: EventType;
  severity: RiskLevel;
  risk_score: number | null;
  actor: string;
  description: string;
  source: DataSource;
  status: EventStatus;
  details: Record<string, unknown>;
  scan_id: string | null;
  incident_id: string | null;
  demo_run_id: string | null;
}

export interface IncidentSummary {
  id: string;
  created_at: string;
  updated_at: string;
  title: string;
  severity: RiskLevel;
  risk_score: number | null;
  status: IncidentStatus;
  source: DataSource;
  scan_id: string | null;
}

export interface IncidentNote {
  id: string;
  created_at: string;
  author: string;
  kind: "note" | "ai_summary" | "system";
  body: string;
}

export interface TimelineEntry {
  at: string;
  kind: "created" | "status_change" | "update" | "note" | "ai_summary" | "event" | "audit";
  title: string;
  detail: string | null;
  actor: string | null;
  ref_id: string | null;
}

export interface AuditEntry {
  id: string;
  created_at: string;
  actor: string;
  action: string;
  details: Record<string, unknown>;
  request_id: string | null;
}

export interface IncidentDetail extends IncidentSummary {
  description: string;
  evidence_summary: string;
  resolution_notes: string | null;
  resolved_at: string | null;
  created_by: string;
  demo_run_id: string | null;
  notes: IncidentNote[];
  events: SecurityEvent[];
  timeline: TimelineEntry[];
  audit: AuditEntry[];
}

export interface DashboardSummary {
  total_scans: number;
  scans_24h: number;
  high_risk_scans: number;
  critical_scans: number;
  open_incidents: number;
  events_24h: number;
  demo_records_present: boolean;
  risk_distribution: Record<RiskLevel, number>;
  recent_scans: ScanSummary[];
  recent_events: SecurityEvent[];
  open_incident_list: IncidentSummary[];
  provenance_note: string;
}

export interface ActivityBucket {
  start: string;
  LOW: number;
  MEDIUM: number;
  HIGH: number;
  CRITICAL: number;
  events: number;
}

export interface DashboardActivity {
  range: "24h" | "7d";
  bucket: "hour" | "day";
  buckets: ActivityBucket[];
}

export interface SystemStatus {
  app: string;
  version: string;
  environment: string;
  database: "ok" | "unavailable";
  groq: { enabled: boolean; configured: boolean; model: string | null; status: "active" | "disabled" | "not_configured" };
  classifier: {
    available: boolean;
    model_version: string | null;
    reason: string | null;
    test_metrics: Record<string, unknown>;
    dataset: Record<string, unknown>;
  };
  reputation: Record<string, string>;
  websocket_clients: number;
  auth_mode: string;
  demo_mode: boolean;
  rate_limiting: boolean;
  privacy: Record<string, unknown>;
  thresholds: Record<string, number>;
  versions: Record<string, string>;
  server_time: string;
}

export interface Scenario {
  id: string;
  title: string;
  description: string;
  steps: string[];
  expected_outcome: string;
}

export interface DemoStep {
  index: number;
  title: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  detail: string | null;
  refs: Record<string, string>;
  at: string | null;
}

export interface DemoRun {
  id: string;
  scenario_id: string;
  status: "running" | "completed" | "failed" | "cancelled";
  steps: DemoStep[];
  started_at: string;
  finished_at: string | null;
  error: string | null;
}

export interface SimulatorStatus {
  running: boolean;
  started_at: string | null;
  interval_seconds: number | null;
  events_generated: number;
  max_seconds: number;
}

export interface AuthSession {
  auth_mode: "open" | "token";
  authenticated: boolean;
  token_required: boolean;
}
