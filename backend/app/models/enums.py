from __future__ import annotations

from enum import StrEnum


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _RISK_ORDER[self]


_RISK_ORDER = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}


class ScanKind(StrEnum):
    MESSAGE = "message"
    URL = "url"


class ContentType(StrEnum):
    AUTO = "auto"
    SMS = "sms"
    EMAIL = "email"
    JOB_OFFER = "job_offer"
    PAYMENT_REQUEST = "payment_request"
    ACCOUNT_VERIFICATION = "account_verification"
    DELIVERY = "delivery"
    PRIZE = "prize"
    CHAT = "chat"
    GENERAL = "general"
    URL = "url"


class DataSource(StrEnum):
    """Provenance: real application activity vs. scripted demo vs. synthetic simulation events."""

    APPLICATION = "application"
    DEMO = "demo"
    SIMULATION = "simulation"


class EventType(StrEnum):
    HIGH_RISK_MESSAGE = "high_risk_message"
    HIGH_RISK_URL = "high_risk_url"
    FAILED_LOGIN_BURST = "failed_login_burst"
    SUSPICIOUS_LOGIN = "suspicious_login"
    RATE_LIMIT = "rate_limit"
    ACCOUNT_TAKEOVER_WARNING = "account_takeover_warning"
    INCIDENT_CREATED = "incident_created"
    INCIDENT_RESOLVED = "incident_resolved"


class EventStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    LINKED = "linked"


class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class NoteKind(StrEnum):
    NOTE = "note"
    AI_SUMMARY = "ai_summary"
    SYSTEM = "system"


class DemoRunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
