"""Explainable, reproducible risk scoring.

score = Σ over categories of min(cap_c, w₁ + 0.5·w₂ + 0.5·w₃ …)   (weights sorted descending per category)

* Each rule contributes at most once (deduplicated by rule_id), so repeated keywords do not inflate scores.
* Category caps bound how much any single kind of evidence can contribute.
* Classifier and LLM contributions are computed by the backend from validated signals and are capped.
* The total is clamped to 0–100. The score is a risk index, NOT a probability of fraud.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.models.enums import RiskLevel
from app.services.detection.types import Finding

SCORING_VERSION = "score-1.0"

DIMINISHING_FACTOR = 0.5

CATEGORY_CAPS: dict[str, int] = {
    # message categories
    "credential_request": 40,
    "payment_request": 30,
    "urgency": 25,
    "impersonation": 15,
    "reward_lure": 25,
    "job_scam": 20,
    "secrecy": 15,
    "verification_bypass": 20,
    "remote_access": 30,
    "download_install": 25,
    "personal_info": 25,
    "prompt_injection": 20,
    "obfuscation": 15,
    "url": 35,  # URL evidence inside a message
    "classifier": 12,
    "llm": 10,
    "combination": 30,
    # URL-scan categories
    "transport": 10,
    "deception": 40,
    "host": 30,
    "brand": 40,
    "redirection": 15,
    "content": 25,
}
DEFAULT_CAP = 20

EvidenceStrength = Literal["none", "limited", "moderate", "strong"]


@dataclass(frozen=True)
class Thresholds:
    medium: int = 25
    high: int = 50
    critical: int = 75

    def level_for(self, score: int) -> RiskLevel:
        if score >= self.critical:
            return RiskLevel.CRITICAL
        if score >= self.high:
            return RiskLevel.HIGH
        if score >= self.medium:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW


@dataclass
class CategoryBreakdown:
    category: str
    rule_ids: list[str]
    raw: float
    cap: int
    points: float

    def as_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "rule_ids": self.rule_ids,
            "raw": round(self.raw, 2),
            "cap": self.cap,
            "points": round(self.points, 2),
        }


@dataclass
class ScoreResult:
    score: int
    level: RiskLevel
    evidence_strength: EvidenceStrength
    breakdown: list[CategoryBreakdown]
    findings: list[Finding]


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """One finding per rule_id (keeps the highest weight; sums match counts)."""
    by_id: dict[str, Finding] = {}
    for f in findings:
        existing = by_id.get(f.rule_id)
        if existing is None:
            by_id[f.rule_id] = f
            continue
        existing.match_count += f.match_count
        if f.weight > existing.weight:
            f.match_count = existing.match_count
            by_id[f.rule_id] = f
    return list(by_id.values())


def _evidence_strength(findings: list[Finding], score: int) -> EvidenceStrength:
    if score == 0:
        return "none"
    deterministic = [f for f in findings if f.source in ("rule", "url_analyzer") and f.points > 0]
    categories = {f.category for f in deterministic}
    high = any(f.severity == "high" for f in deterministic)
    if len(categories) >= 4 or (len(categories) >= 2 and high):
        return "strong"
    if len(categories) >= 2 or high:
        return "moderate"
    return "limited"


def score_findings(findings: list[Finding], thresholds: Thresholds | None = None) -> ScoreResult:
    thresholds = thresholds or Thresholds()
    unique = deduplicate(findings)

    by_category: dict[str, list[Finding]] = {}
    for f in unique:
        f.weight = max(0, f.weight)
        f.points = 0.0
        by_category.setdefault(f.category, []).append(f)

    breakdown: list[CategoryBreakdown] = []
    total = 0.0
    for category, items in sorted(by_category.items()):
        cap = CATEGORY_CAPS.get(category, DEFAULT_CAP)
        items.sort(key=lambda x: (-x.weight, x.rule_id))
        remaining = float(cap)
        raw = 0.0
        for index, item in enumerate(items):
            contribution = item.weight * (1.0 if index == 0 else DIMINISHING_FACTOR)
            raw += contribution
            granted = min(contribution, remaining)
            item.points = round(granted, 2)
            remaining -= granted
        points = cap - remaining
        total += points
        breakdown.append(CategoryBreakdown(category, [i.rule_id for i in items], raw, cap, points))

    score = round(min(100.0, max(0.0, total)))
    ordered = sorted(unique, key=lambda f: (-f.points, -f.weight, f.rule_id))
    return ScoreResult(
        score=score,
        level=thresholds.level_for(score),
        evidence_strength=_evidence_strength(ordered, score),
        breakdown=sorted(breakdown, key=lambda b: -b.points),
        findings=ordered,
    )


def classifier_points(probability: float, cap: int = CATEGORY_CAPS["classifier"]) -> int:
    """Maps the classifier's spam probability to a bounded contribution: 0 below 0.5, linear up to the
    cap at ≥ 0.95. The classifier can raise a score modestly but never decide it alone."""
    if probability < 0.5:
        return 0
    return round(cap * min(1.0, (probability - 0.5) / 0.45))


LLM_UNCORROBORATED_SIGNAL_WEIGHT = 5
