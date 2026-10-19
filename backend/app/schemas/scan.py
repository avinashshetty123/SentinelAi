from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.models.enums import ContentType, DataSource, RiskLevel, ScanKind
from app.schemas.common import ORMModel


class MessageScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000, description="Message to analyze (not stored)")
    content_type: ContentType = ContentType.AUTO
    use_llm: bool = Field(default=True, description="Allow sending minimized text to the configured LLM")

    @field_validator("text")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("text must not be blank")
        return v

    @field_validator("content_type")
    @classmethod
    def _not_url(cls, v: ContentType) -> ContentType:
        if v == ContentType.URL:
            raise ValueError("use the URL scan endpoint for URLs")
        return v


class UrlScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    use_llm: bool = Field(default=False, description="Ask the LLM to explain the extracted URL features")


class FindingOut(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: str
    source: str
    weight: int
    points: float
    explanation: str
    evidence: str | None = None
    match_count: int = 1
    corroborated_by: list[str] = Field(default_factory=list)


class FindingStored(ORMModel):
    rule_id: str
    title: str
    category: str
    severity: str
    source: str
    weight: int
    points: float
    explanation: str
    evidence_excerpt: str | None = None


class ScoreCategory(BaseModel):
    category: str
    rule_ids: list[str]
    raw: float
    cap: int
    points: float


class LLMInfo(BaseModel):
    status: str
    model: str | None = None
    used: bool = False
    summary: str | None = None
    signals_accepted: int = 0
    signals_discarded: int = 0
    latency_ms: int | None = None


class ClassifierInfo(BaseModel):
    status: Literal["available", "unavailable", "disabled", "not_applicable"]
    model_version: str | None = None
    spam_probability: float | None = None
    points: int = 0
    note: str | None = None


class ReputationInfo(BaseModel):
    status: Literal["not_configured", "unavailable", "ok"]
    provider: str | None = None
    note: str


class UrlDetails(BaseModel):
    normalized_url: str
    display_target: str
    scheme: str
    scheme_assumed: bool
    host: str
    host_unicode: str
    registered_domain: str | None
    subdomain: str
    port: int | None
    is_ip: bool
    is_official_brand_domain: bool
    reputation: ReputationInfo


class Versions(BaseModel):
    rule_version: str
    scoring_version: str
    classifier_version: str | None = None


class PrivacyInfo(BaseModel):
    raw_text_stored: bool = False
    excerpts_stored: bool
    sent_to_llm: bool


class ScanResult(BaseModel):
    id: uuid.UUID
    kind: ScanKind
    content_type: str
    source: DataSource
    created_at: datetime
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    evidence_strength: str
    summary: str
    ai_summary: str | None = None
    findings: list[FindingOut]
    recommendations: list[str]
    limitations: list[str]
    score_breakdown: list[ScoreCategory]
    llm: LLMInfo
    classifier: ClassifierInfo
    url_details: UrlDetails | None = None
    extracted_urls: list[str] = Field(default_factory=list)
    versions: Versions
    privacy: PrivacyInfo
    input_length: int
    related_event_id: uuid.UUID | None = None
    related_incident_id: uuid.UUID | None = None


class ScanSummary(ORMModel):
    id: uuid.UUID
    kind: ScanKind
    content_type: str
    source: DataSource
    created_at: datetime
    risk_score: int
    risk_level: RiskLevel
    evidence_strength: str
    summary: str
    target_display: str | None = None
    llm_status: str
    url_count: int


class ScanDetail(ScanSummary):
    ai_summary: str | None = None
    recommendations: list[str]
    limitations: list[str]
    score_breakdown: list[ScoreCategory]
    llm_model: str | None = None
    sent_to_llm: bool
    classifier_status: str
    classifier_version: str | None = None
    classifier_probability: float | None = None
    rule_version: str
    scoring_version: str
    input_length: int
    expires_at: datetime
    findings: list[FindingStored]
