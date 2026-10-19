"""Analyze-only tools (nothing is stored): e-mail header forensics and the rule catalogue."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.ratelimit import rate_limit
from app.core.security import Principal, require_principal
from app.models.enums import RiskLevel
from app.schemas.scan import FindingOut, ScoreCategory
from app.services import explanations
from app.services.detection.email_headers import EMAIL_RULE_VERSION, analyze_email_headers
from app.services.detection.message_rules import COMBINATION_RULES, RULE_VERSION, RULES
from app.services.detection.url_analyzer import URL_RULE_VERSION
from app.services.scoring.engine import CATEGORY_CAPS, DIMINISHING_FACTOR, SCORING_VERSION, Thresholds, score_findings

router = APIRouter(tags=["tools"])


class EmailHeaderRequest(BaseModel):
    headers: str = Field(min_length=10, max_length=30_000, description="Raw e-mail headers ('Show original')")


class EmailHop(BaseModel):
    from_: str | None = Field(default=None, alias="from")
    by: str | None = None
    ip: str | None = None

    model_config = {"populate_by_name": True}


class EmailHeaderResult(BaseModel):
    risk_score: int
    risk_level: RiskLevel
    evidence_strength: str
    summary: str
    from_address: str | None
    from_display: str | None
    from_domain: str | None
    reply_to_domain: str | None
    return_path_domain: str | None
    subject: str | None
    auth: dict[str, str]
    hops: list[EmailHop]
    findings: list[FindingOut]
    score_breakdown: list[ScoreCategory]
    recommendations: list[str]
    limitations: list[str]
    rule_version: str = EMAIL_RULE_VERSION


@router.post(
    "/tools/email-headers",
    response_model=EmailHeaderResult,
    dependencies=[Depends(rate_limit("scans"))],
    summary="Analyze raw e-mail headers for spoofing (offline, not stored)",
)
async def email_headers(body: EmailHeaderRequest, _: Principal = Depends(require_principal)) -> EmailHeaderResult:
    s = get_settings()
    result = analyze_email_headers(body.headers)
    score = score_findings(
        result.findings, Thresholds(s.risk_threshold_medium, s.risk_threshold_high, s.risk_threshold_critical)
    )
    recs = explanations.build_recommendations(score.level, score.findings)
    if any(f.category == "authentication" and f.points > 0 for f in score.findings):
        recs.insert(0, "Do not trust the From address: the receiving server could not authenticate the sender.")
    return EmailHeaderResult(
        risk_score=score.score,
        risk_level=score.level,
        evidence_strength=score.evidence_strength,
        summary=explanations.build_summary("email", score.level, score.score, score.findings),
        from_address=result.from_address,
        from_display=result.from_display,
        from_domain=result.from_domain,
        reply_to_domain=result.reply_to_domain,
        return_path_domain=result.return_path_domain,
        subject=result.subject,
        auth=result.auth,
        hops=[EmailHop(**h) for h in result.hops],
        findings=[
            FindingOut(
                rule_id=f.rule_id,
                title=f.title,
                category=f.category,
                severity=f.severity,
                source=f.source,
                weight=f.weight,
                points=f.points,
                explanation=f.explanation,
                evidence=f.evidence,
            )
            for f in score.findings
        ],
        score_breakdown=[ScoreCategory(**b.as_dict()) for b in score.breakdown],
        recommendations=recs[:6],
        limitations=[
            "Results rely on what the receiving mail server recorded; no DNS lookups were made.",
            "Headers can be partially forged above the first trusted relay. Pasted headers are not stored.",
        ],
    )


class RuleOut(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: str
    weight: int
    explanation: str


class RuleCatalogue(BaseModel):
    versions: dict[str, str]
    thresholds: dict[str, int]
    diminishing_factor: float
    category_caps: dict[str, int]
    message_rules: list[RuleOut]
    combination_rules: list[RuleOut]


@router.get("/system/rules", response_model=RuleCatalogue, summary="Every detection rule and weight, from the code")
async def rules(_: Principal = Depends(require_principal)) -> RuleCatalogue:
    s = get_settings()
    msg = [
        RuleOut(
            rule_id=r.rule_id,
            title=r.title,
            category=r.category,
            severity=r.severity,
            weight=r.weight,
            explanation=r.explanation,
        )
        for r in RULES
    ]
    msg.append(
        RuleOut(
            rule_id="MSG_OBFUSCATION",
            title="Hidden or disguised characters",
            category="obfuscation",
            severity="medium",
            weight=12,
            explanation="Zero-width/bidi characters or words mixing lookalike alphabets.",
        )
    )
    return RuleCatalogue(
        versions={
            "message": RULE_VERSION,
            "url": URL_RULE_VERSION,
            "email": EMAIL_RULE_VERSION,
            "scoring": SCORING_VERSION,
        },
        thresholds={
            "medium": s.risk_threshold_medium,
            "high": s.risk_threshold_high,
            "critical": s.risk_threshold_critical,
        },
        diminishing_factor=DIMINISHING_FACTOR,
        category_caps=CATEGORY_CAPS,
        message_rules=msg,
        combination_rules=[RuleOut(**c) for c in COMBINATION_RULES],
    )
