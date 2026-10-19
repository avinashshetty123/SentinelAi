from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.event import EventOut
from app.schemas.incident import IncidentSummaryOut
from app.schemas.scan import ScanSummary


class ProviderStatus(BaseModel):
    enabled: bool
    configured: bool
    model: str | None
    status: Literal["active", "disabled", "not_configured"]


class ClassifierStatus(BaseModel):
    available: bool
    model_version: str | None = None
    reason: str | None = None
    test_metrics: dict[str, Any] = Field(default_factory=dict)
    dataset: dict[str, Any] = Field(default_factory=dict)


class SystemStatus(BaseModel):
    app: str
    version: str
    environment: str
    database: Literal["ok", "unavailable"]
    groq: ProviderStatus
    classifier: ClassifierStatus
    reputation: dict[str, str]
    websocket_clients: int
    auth_mode: str
    demo_mode: bool
    rate_limiting: bool
    privacy: dict[str, Any]
    thresholds: dict[str, int]
    versions: dict[str, str]
    server_time: datetime


class LLMCheckResponse(BaseModel):
    status: str
    model: str | None
    latency_ms: int | None
    message: str


class RiskDistribution(BaseModel):
    LOW: int = 0
    MEDIUM: int = 0
    HIGH: int = 0
    CRITICAL: int = 0


class DashboardSummary(BaseModel):
    total_scans: int
    scans_24h: int
    high_risk_scans: int
    critical_scans: int
    open_incidents: int
    events_24h: int
    demo_records_present: bool
    risk_distribution: RiskDistribution
    recent_scans: list[ScanSummary]
    recent_events: list[EventOut]
    open_incident_list: list[IncidentSummaryOut]
    provenance_note: str


class ActivityBucket(BaseModel):
    start: datetime
    LOW: int = 0
    MEDIUM: int = 0
    HIGH: int = 0
    CRITICAL: int = 0
    events: int = 0


class DashboardActivity(BaseModel):
    range: Literal["24h", "7d"]
    bucket: Literal["hour", "day"]
    buckets: list[ActivityBucket]


class ScenarioOut(BaseModel):
    id: str
    title: str
    description: str
    steps: list[str]
    expected_outcome: str


class DemoStep(BaseModel):
    index: int
    title: str
    status: Literal["pending", "running", "completed", "failed", "skipped"]
    detail: str | None = None
    refs: dict[str, str] = Field(default_factory=dict)
    at: datetime | None = None


class DemoRunOut(BaseModel):
    id: uuid.UUID
    scenario_id: str
    status: str
    steps: list[DemoStep]
    started_at: datetime
    finished_at: datetime | None
    error: str | None


class DemoStatus(BaseModel):
    scenario_id: str
    run: DemoRunOut | None


class SimulatorStatus(BaseModel):
    running: bool
    started_at: datetime | None = None
    interval_seconds: float | None = None
    events_generated: int = 0
    max_seconds: int


class SimulatorStart(BaseModel):
    interval_seconds: float = Field(default=4.0, ge=1.0, le=60.0)


class ResetResult(BaseModel):
    deleted: dict[str, int]
    message: str
