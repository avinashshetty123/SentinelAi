"""Analysis pipeline orchestration for message and URL scans.

validate → normalize → extract features → rules → URL checks → classifier → (optional) LLM →
validate LLM output → score → explain → persist metadata → publish events / incidents.
"""

from __future__ import annotations

import asyncio
import re
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.database.base import utcnow
from app.models import Incident, Scan, ScanFinding, SecurityEvent
from app.models.enums import ContentType, DataSource, EventType, RiskLevel, ScanKind
from app.schemas.event import EventCreate
from app.schemas.scan import (
    ClassifierInfo,
    FindingOut,
    Highlight,
    LLMInfo,
    MessageScanRequest,
    PrivacyInfo,
    ReputationInfo,
    ScanResult,
    ScoreCategory,
    UrlDetails,
    UrlPart,
    UrlReputation,
    UrlScanRequest,
    Versions,
)
from app.services import explanations
from app.services.detection.classifier import get_classifier
from app.services.detection.message_rules import RULE_VERSION, combination_findings, run_message_rules
from app.services.detection.text import extract_urls, minimize_for_llm, normalize_text
from app.services.detection.types import Finding
from app.services.detection.url_analyzer import URL_RULE_VERSION, UrlValidationError, analyze_url
from app.services.events.service import broadcast_event, create_event
from app.services.incidents import create_incident_record, incident_created_side_effects
from app.services.llm.groq_service import LLMOutcome, get_groq_service
from app.services.llm.schemas import LLMAnalysis, SignalCategory
from app.services.reputation.findings import reputation_findings
from app.services.reputation.provider import get_reputation_provider
from app.services.scoring.engine import (
    LLM_UNCORROBORATED_SIGNAL_WEIGHT,
    SCORING_VERSION,
    Thresholds,
    classifier_points,
    score_findings,
)
from app.websocket.manager import manager

_SENT_STATUSES = {"ok", "timeout", "provider_error", "invalid_output", "auth_error"}
_URL_OR_PHONE = re.compile(r"(https?://|www\.|\b[a-z0-9-]+\.(com|net|org|xyz|io|ly)\b|\+?\d[\d\s-]{7,}\d)", re.I)

CONTENT_TYPE_KEYWORDS: dict[ContentType, tuple[str, ...]] = {
    ContentType.JOB_OFFER: (
        "job",
        "hiring",
        "salary",
        "recruit",
        "interview",
        "position",
        "work from home",
        "part-time",
        "part time",
        "vacancy",
        "hr team",
    ),
    ContentType.PAYMENT_REQUEST: (
        "invoice",
        "payment",
        "pay ",
        "transfer",
        "upi",
        "amount due",
        "outstanding",
        "bill",
        "refund",
    ),
    ContentType.ACCOUNT_VERIFICATION: (
        "verify",
        "kyc",
        "otp",
        "password",
        "login",
        "sign in",
        "suspended",
        "account locked",
        "security alert",
    ),
    ContentType.DELIVERY: ("parcel", "package", "delivery", "shipment", "courier", "tracking", "redeliver"),
    ContentType.PRIZE: ("won", "prize", "lottery", "winner", "reward", "jackpot", "lucky draw", "gift"),
}


@dataclass
class AnalysisContext:
    source: DataSource = DataSource.APPLICATION
    demo_run_id: uuid.UUID | None = None
    actor: str = "operator"
    auto_incident: bool | None = None  # None → use AUTO_INCIDENT_MIN_LEVEL; demo scenarios pass False


@dataclass
class _Outcome:
    scan: Scan | None
    event: SecurityEvent | None
    incident: Incident | None
    id: uuid.UUID
    created_at: datetime


MAX_MESSAGE_REPUTATION_LOOKUPS = 2  # protects the VirusTotal free-tier quota
_QUOTE_CHARS = "\"'“”‘’…. "


def _highlights(findings: list[Finding], text_length: int) -> list[Highlight]:
    out: list[Highlight] = []
    for f in findings:
        for start, end in f.spans:
            if 0 <= start < end <= text_length:
                out.append(
                    Highlight(
                        start=start, end=end, rule_id=f.rule_id, title=f.title, category=f.category, source=f.source
                    )
                )
    out.sort(key=lambda h: (h.start, -(h.end - h.start)))
    return out[:80]


def _find_spans(text: str, needle: str, limit: int = 5) -> list[tuple[int, int]]:
    if not needle:
        return []
    hay, ndl = text.casefold(), needle.casefold()
    if len(hay) != len(text) or len(ndl) != len(needle):  # casefold changed lengths; use exact search
        hay, ndl = text, needle
    spans: list[tuple[int, int]] = []
    start = 0
    while len(spans) < limit:
        idx = hay.find(ndl, start)
        if idx < 0:
            break
        spans.append((idx, idx + len(ndl)))
        start = idx + len(ndl)
    return spans


def detect_content_type(text: str) -> ContentType:
    lowered = text.lower()
    if re.match(r"^\s*(subject|from|to)\s*:", lowered):
        return ContentType.EMAIL
    scores = {ct: sum(lowered.count(k) for k in kws) for ct, kws in CONTENT_TYPE_KEYWORDS.items()}
    best, hits = max(scores.items(), key=lambda kv: kv[1])
    if hits > 0:
        return best
    return ContentType.SMS if len(text) <= 320 else ContentType.GENERAL


def _fold(value: str) -> str:
    value = unicodedata.normalize("NFKC", value).casefold()
    value = value.strip().strip("\"'“”‘’…. ")
    return re.sub(r"\s+", " ", value)


def _thresholds(settings: Settings) -> Thresholds:
    return Thresholds(settings.risk_threshold_medium, settings.risk_threshold_high, settings.risk_threshold_critical)


def _finding_out(f: Finding) -> FindingOut:
    return FindingOut(
        rule_id=f.rule_id,
        title=f.title,
        category=f.category,
        severity=f.severity,
        source=f.source,
        weight=f.weight,
        points=f.points,
        explanation=f.explanation,
        evidence=f.evidence,
        match_count=f.match_count,
        corroborated_by=f.corroborated_by,
    )


def _vet_llm_recommendations(recs: list[str]) -> list[str]:
    # The LLM must never supply links or phone numbers to contact.
    return [r for r in recs if not _URL_OR_PHONE.search(r)]


def _apply_llm_signals(
    outcome: LLMOutcome[LLMAnalysis], minimized: str, findings: list[Finding]
) -> tuple[list[Finding], int, int]:
    """Accepts only LLM signals whose evidence is an exact (normalized) quote of the text that was sent.
    Signals in categories already covered by rules corroborate instead of adding points."""
    assert outcome.data is not None
    haystack = _fold(minimized)
    deterministic_categories = {f.category for f in findings if f.source in ("rule", "url_analyzer")}
    accepted: list[Finding] = []
    discarded = 0
    seen_categories: set[str] = set()
    for signal in outcome.data.social_engineering_signals:
        quote = _fold(signal.evidence)
        if len(quote) < 3 or quote not in haystack:
            discarded += 1
            continue
        category = "url" if signal.category == SignalCategory.LINK_LURE else signal.category.value
        corroborates = category in deterministic_categories
        if corroborates:
            for f in findings:
                if f.category == category and f.source in ("rule", "url_analyzer"):
                    f.corroborated_by.append("llm")
                    break
        weight = 0
        if not corroborates and signal.category != SignalCategory.OTHER and category not in seen_categories:
            weight = LLM_UNCORROBORATED_SIGNAL_WEIGHT
        seen_categories.add(category)
        accepted.append(
            Finding(
                rule_id=f"LLM_{signal.category.value.upper()}_{len(accepted) + 1}",
                title=f"AI: {signal.signal}" + (" (corroborates rule evidence)" if corroborates else ""),
                category="llm",
                severity="low",
                source="llm",
                weight=weight,
                explanation=signal.explanation,
                evidence=signal.evidence[:160],
            )
        )
    return accepted, len(accepted), discarded


def _attach_llm_spans(findings: list[Finding], text: str) -> None:
    for f in findings:
        if f.source == "llm" and f.evidence and "[NUMBER]" not in f.evidence and "[EMAIL]" not in f.evidence:
            f.spans = _find_spans(text, f.evidence.strip().strip(_QUOTE_CHARS), limit=2)


def _llm_info(outcome: LLMOutcome[LLMAnalysis] | None, used: bool, accepted: int = 0, discarded: int = 0) -> LLMInfo:
    if outcome is None:
        return LLMInfo(status="skipped")
    return LLMInfo(
        status=outcome.status,
        model=outcome.model,
        used=used,
        summary=outcome.data.summary if outcome.ok and outcome.data else None,
        signals_accepted=accepted,
        signals_discarded=discarded,
        latency_ms=outcome.latency_ms,
    )


async def _persist_and_publish(
    session: AsyncSession,
    *,
    persist: bool = True,
    settings: Settings,
    ctx: AnalysisContext,
    kind: ScanKind,
    content_type: str,
    score_result,
    summary: str,
    ai_summary: str | None,
    recommendations: list[str],
    limitations: list[str],
    llm: LLMInfo,
    sent_to_llm: bool,
    classifier: ClassifierInfo,
    rule_version: str,
    input_length: int,
    url_count: int,
    target_display: str | None,
) -> _Outcome:
    if not persist:
        return _Outcome(scan=None, event=None, incident=None, id=uuid.uuid4(), created_at=utcnow())
    scan = Scan(
        kind=kind,
        content_type=content_type,
        source=ctx.source,
        demo_run_id=ctx.demo_run_id,
        risk_score=score_result.score,
        risk_level=score_result.level,
        evidence_strength=score_result.evidence_strength,
        summary=summary,
        ai_summary=ai_summary if settings.store_ai_summaries else None,
        recommendations=recommendations,
        limitations=limitations,
        score_breakdown=[b.as_dict() for b in score_result.breakdown],
        llm_status=llm.status,
        llm_model=llm.model if llm.used else None,
        sent_to_llm=sent_to_llm,
        classifier_status=classifier.status,
        classifier_version=classifier.model_version,
        classifier_probability=classifier.spam_probability,
        rule_version=rule_version,
        scoring_version=SCORING_VERSION,
        input_length=input_length,
        url_count=url_count,
        target_display=target_display,
        expires_at=utcnow() + timedelta(days=settings.scan_retention_days),
    )
    scan.findings = [
        ScanFinding(
            position=i,
            rule_id=f.rule_id,
            title=f.title[:160],
            category=f.category,
            severity=f.severity,
            source=f.source,
            weight=f.weight,
            points=f.points,
            explanation=f.explanation,
            evidence_excerpt=(f.evidence[:300] if f.evidence else None) if settings.store_finding_excerpts else None,
        )
        for i, f in enumerate(score_result.findings)
    ]
    session.add(scan)
    await session.flush()

    level: RiskLevel = score_result.level
    event: SecurityEvent | None = None
    incident: Incident | None = None
    if level.rank >= RiskLevel(settings.event_min_level).rank:
        top = [f.title for f in score_result.findings if f.points > 0 and f.source != "llm"][:3]
        label = "message" if kind == ScanKind.MESSAGE else "URL"
        target = f" ({target_display})" if target_display else f" ({content_type.replace('_', ' ')})"
        event = await create_event(
            session,
            EventCreate(
                event_type=EventType.HIGH_RISK_MESSAGE if kind == ScanKind.MESSAGE else EventType.HIGH_RISK_URL,
                severity=level,
                risk_score=score_result.score,
                actor="demo-scenario" if ctx.source == DataSource.DEMO else "sentinel-analyzer",
                description=f"{level.value} risk {label}{target} scored {score_result.score}/100. "
                f"Top indicators: {'; '.join(top) or 'n/a'}."[:500],
                source=ctx.source,
                scan_id=scan.id,
                demo_run_id=ctx.demo_run_id,
                details={"kind": kind.value, "evidence_strength": score_result.evidence_strength},
            ),
            commit=False,
        )

        auto = ctx.auto_incident
        if auto is None:
            min_level = settings.auto_incident_min_level
            auto = min_level != "NONE" and level.rank >= RiskLevel(min_level).rank
        if auto:
            evidence = "\n".join(
                f"- {f.title} ({f.source}, +{f.points:g})" for f in score_result.findings if f.points > 0
            )[:4000]
            incident = await create_incident_record(
                session,
                title=f"{level.value.title()} risk {label} detected"[:200],
                description=f"Automatically opened from scan {scan.id} ({content_type}). {summary}"[:4000],
                severity=level,
                risk_score=score_result.score,
                evidence_summary=evidence,
                scan_id=scan.id,
                event_ids=[event.id],
                actor="sentinel-analyzer",
                source=ctx.source,
                demo_run_id=ctx.demo_run_id,
            )

    await session.commit()
    await session.refresh(scan)
    await manager.broadcast(
        "scan.created",
        {
            "id": str(scan.id),
            "kind": kind.value,
            "risk_level": level.value,
            "risk_score": scan.risk_score,
            "source": ctx.source.value,
        },
    )
    if event is not None:
        await session.refresh(event)
        await broadcast_event(event)
    if incident is not None:
        await incident_created_side_effects(session, incident)
    return _Outcome(scan=scan, event=event, incident=incident, id=scan.id, created_at=scan.created_at)


async def analyze_message(
    session: AsyncSession, request: MessageScanRequest, ctx: AnalysisContext | None = None
) -> ScanResult:
    ctx = ctx or AnalysisContext()
    settings = get_settings()
    if len(request.text) > settings.max_message_chars:
        raise AppError(422, "validation_error", f"text exceeds {settings.max_message_chars} characters")

    normalized = normalize_text(request.text)
    content_type = (
        detect_content_type(normalized.text) if request.content_type == ContentType.AUTO else request.content_type
    )
    findings = run_message_rules(normalized)

    urls = extract_urls(normalized.text)
    analyzed_urls = []
    for url in urls:
        try:
            ua = analyze_url(url, settings.max_url_chars)
        except UrlValidationError:
            continue
        analyzed_urls.append(ua)
        url_spans = _find_spans(normalized.text, url, limit=3)
        for f in ua.findings:
            if f.weight <= 0:
                continue
            f.category = "url"
            f.evidence = f"{ua.display_target}: {f.evidence}" if f.evidence else ua.display_target
            f.spans = url_spans
            findings.append(f)

    # External reputation for embedded links (bounded number of lookups, run concurrently).
    url_reputations: list[UrlReputation] = []
    provider = get_reputation_provider()
    if provider.name != "none" and analyzed_urls:
        targets = analyzed_urls[:MAX_MESSAGE_REPUTATION_LOOKUPS]
        reports = await asyncio.gather(*(provider.lookup(ua.normalized_url) for ua in targets))
        for ua, info in zip(targets, reports, strict=True):
            url_reputations.append(UrlReputation(url=ua.display_target, reputation=info))
            for f in reputation_findings(info, ua.display_target):
                f.spans = _find_spans(normalized.text, ua.host, limit=2)
                findings.append(f)
    findings.extend(combination_findings(findings, len(urls)))

    # Classifier (bounded contribution)
    classifier_model = get_classifier() if settings.classifier_enabled else None
    if not settings.classifier_enabled:
        clf = ClassifierInfo(status="disabled")
    elif classifier_model is None:
        clf = ClassifierInfo(status="unavailable", note="Classifier artifact not loaded")
    else:
        pred = classifier_model.predict(normalized.text)
        pts = classifier_points(pred.spam_probability)
        clf = ClassifierInfo(
            status="available",
            model_version=pred.model_version,
            spam_probability=round(pred.spam_probability, 4),
            points=pts,
            note="Probability from a baseline model trained on the UCI SMS Spam Collection (spam vs. ham). "
            "It reflects spam-like wording, not a verified fraud probability.",
        )
        if pts > 0:
            findings.append(
                Finding(
                    rule_id="CLF_SPAM_LANGUAGE",
                    title="Spam-like wording (statistical classifier)",
                    category="classifier",
                    severity="medium" if pred.spam_probability >= 0.85 else "low",
                    source="classifier",
                    weight=pts,
                    explanation=f"A TF-IDF + logistic-regression model estimates a {pred.spam_probability:.0%} "
                    "probability that this text belongs to the spam class of its training data. Its "
                    "contribution to the score is capped.",
                )
            )

    # Optional LLM analysis
    service = get_groq_service()
    outcome: LLMOutcome[LLMAnalysis] | None = None
    accepted = discarded = 0
    minimized = ""
    if request.use_llm:
        minimized = minimize_for_llm(normalized.text, settings.groq_max_input_chars)
        rule_context = [f"{f.rule_id}: {f.title}" for f in findings if f.source != "classifier"]
        outcome = await service.analyze_message(minimized, content_type.value, rule_context)
        if outcome.ok:
            llm_findings, accepted, discarded = _apply_llm_signals(outcome, minimized, findings)
            _attach_llm_spans(llm_findings, normalized.text)
            findings.extend(llm_findings)
    else:
        outcome = LLMOutcome(status="skipped")
    sent = outcome.status in _SENT_STATUSES or (outcome.status == "rate_limited" and outcome.latency_ms is not None)
    llm = _llm_info(outcome, used=outcome.ok, accepted=accepted, discarded=discarded)

    score = score_findings(findings, _thresholds(settings))
    summary = explanations.build_summary("message", score.level, score.score, score.findings)
    recommendations = explanations.build_recommendations(score.level, score.findings)
    limitations = list(explanations.BASE_LIMITATIONS_MESSAGE)
    if outcome.ok and outcome.data:
        for rec in _vet_llm_recommendations(outcome.data.recommendations):
            if len(recommendations) < 7 and rec not in recommendations:
                recommendations.append(rec)
        limitations.extend(outcome.data.limitations[:2])
    elif request.use_llm:
        limitations.append(
            "AI explanation unavailable for this scan ("
            + outcome.status.replace("_", " ")
            + "); results use deterministic rules and templates only."
        )

    result = await _persist_and_publish(
        session,
        persist=request.persist,
        settings=settings,
        ctx=ctx,
        kind=ScanKind.MESSAGE,
        content_type=content_type.value,
        score_result=score,
        summary=summary,
        ai_summary=llm.summary,
        recommendations=recommendations,
        limitations=limitations,
        llm=llm,
        sent_to_llm=sent,
        classifier=clf,
        rule_version=RULE_VERSION,
        input_length=normalized.original_length,
        url_count=len(urls),
        target_display=None,
    )
    return ScanResult(
        id=result.id,
        kind=ScanKind.MESSAGE,
        content_type=content_type.value,
        source=ctx.source,
        created_at=result.created_at,
        risk_score=score.score,
        risk_level=score.level,
        evidence_strength=score.evidence_strength,
        summary=summary,
        ai_summary=llm.summary,
        findings=[_finding_out(f) for f in score.findings],
        recommendations=recommendations,
        limitations=limitations,
        score_breakdown=[ScoreCategory(**b.as_dict()) for b in score.breakdown],
        llm=llm,
        classifier=clf,
        extracted_urls=urls,
        versions=Versions(
            rule_version=f"{RULE_VERSION}+{URL_RULE_VERSION}",
            scoring_version=SCORING_VERSION,
            classifier_version=clf.model_version,
        ),
        privacy=PrivacyInfo(excerpts_stored=settings.store_finding_excerpts, sent_to_llm=sent),
        input_length=normalized.original_length,
        related_event_id=result.event.id if result.event else None,
        related_incident_id=result.incident.id if result.incident else None,
        persisted=request.persist,
        analyzed_text=normalized.text,
        highlights=_highlights(score.findings, len(normalized.text)),
        url_reputations=url_reputations,
    )


async def analyze_url_scan(
    session: AsyncSession, request: UrlScanRequest, ctx: AnalysisContext | None = None
) -> ScanResult:
    ctx = ctx or AnalysisContext()
    settings = get_settings()
    try:
        ua = analyze_url(request.url, settings.max_url_chars)
    except UrlValidationError as exc:
        raise AppError(422, "invalid_url", str(exc)) from exc

    provider = get_reputation_provider()
    if request.check_reputation:
        reputation = await provider.lookup(ua.normalized_url)
    else:
        reputation = ReputationInfo(
            status="skipped",
            provider=None if provider.name == "none" else provider.name,
            note="Reputation lookup was not requested for this scan.",
        )
    findings = [*ua.findings, *reputation_findings(reputation)]
    score = score_findings(findings, _thresholds(settings))

    outcome: LLMOutcome[LLMAnalysis]
    if request.use_llm:
        features = [{"rule_id": f.rule_id, "title": f.title, "evidence": f.evidence or ""} for f in score.findings]
        url_without_query = ua.normalized_url.split("?", 1)[0]
        outcome = await get_groq_service().explain_url(url_without_query, features)
    else:
        outcome = LLMOutcome(status="skipped")
    sent = outcome.status in _SENT_STATUSES or (outcome.status == "rate_limited" and outcome.latency_ms is not None)
    # For URLs the LLM only explains; it never adds score points.
    llm = _llm_info(outcome, used=outcome.ok)

    summary = explanations.build_summary("url", score.level, score.score, score.findings)
    recommendations = explanations.build_recommendations(score.level, score.findings)
    limitations = list(explanations.BASE_LIMITATIONS_URL)
    if outcome.ok and outcome.data:
        for rec in _vet_llm_recommendations(outcome.data.recommendations):
            if len(recommendations) < 7 and rec not in recommendations:
                recommendations.append(rec)
    elif request.use_llm:
        limitations.append("AI explanation unavailable for this scan (" + outcome.status.replace("_", " ") + ").")

    clf = ClassifierInfo(status="not_applicable")
    result = await _persist_and_publish(
        session,
        persist=request.persist,
        settings=settings,
        ctx=ctx,
        kind=ScanKind.URL,
        content_type=ContentType.URL.value,
        score_result=score,
        summary=summary,
        ai_summary=llm.summary,
        recommendations=recommendations,
        limitations=limitations,
        llm=llm,
        sent_to_llm=sent,
        classifier=clf,
        rule_version=URL_RULE_VERSION,
        input_length=ua.input_length,
        url_count=1,
        target_display=ua.display_target[:300],
    )
    return ScanResult(
        id=result.id,
        kind=ScanKind.URL,
        content_type=ContentType.URL.value,
        source=ctx.source,
        created_at=result.created_at,
        risk_score=score.score,
        risk_level=score.level,
        evidence_strength=score.evidence_strength,
        summary=summary,
        ai_summary=llm.summary,
        findings=[_finding_out(f) for f in score.findings],
        recommendations=recommendations,
        limitations=limitations,
        score_breakdown=[ScoreCategory(**b.as_dict()) for b in score.breakdown],
        llm=llm,
        classifier=clf,
        url_details=UrlDetails(
            normalized_url=ua.normalized_url,
            display_target=ua.display_target,
            scheme=ua.scheme,
            scheme_assumed=ua.scheme_assumed,
            host=ua.host,
            host_unicode=ua.host_unicode,
            registered_domain=ua.registered_domain,
            subdomain=ua.subdomain,
            port=ua.port,
            is_ip=ua.is_ip,
            is_official_brand_domain=ua.is_official_brand_domain,
            reputation=reputation,
            parts=[UrlPart(**p) for p in ua.parts],
        ),
        versions=Versions(rule_version=URL_RULE_VERSION, scoring_version=SCORING_VERSION),
        privacy=PrivacyInfo(excerpts_stored=settings.store_finding_excerpts, sent_to_llm=sent),
        input_length=ua.input_length,
        related_event_id=result.event.id if result.event else None,
        related_incident_id=result.incident.id if result.incident else None,
        persisted=request.persist,
    )
