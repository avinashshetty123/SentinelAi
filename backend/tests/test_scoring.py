from __future__ import annotations

import copy

import pytest

from app.models.enums import RiskLevel
from app.services.detection.message_rules import run_message_rules
from app.services.detection.text import normalize_text
from app.services.detection.types import Finding
from app.services.scoring.engine import CATEGORY_CAPS, Thresholds, classifier_points, score_findings


def f(rule_id: str, category: str, weight: int, severity: str = "medium", source: str = "rule") -> Finding:
    return Finding(rule_id=rule_id, title=rule_id, category=category, severity=severity,  # type: ignore[arg-type]
                   source=source, weight=weight, explanation="x")  # type: ignore[arg-type]


@pytest.mark.parametrize(("score", "level"), [(0, "LOW"), (24, "LOW"), (25, "MEDIUM"), (49, "MEDIUM"), (50, "HIGH"),
                                              (74, "HIGH"), (75, "CRITICAL"), (100, "CRITICAL")])
def test_default_thresholds(score: int, level: str) -> None:
    assert Thresholds().level_for(score).value == level


def test_custom_thresholds() -> None:
    assert Thresholds(10, 20, 30).level_for(25) == RiskLevel.HIGH


def test_empty_findings_score_zero() -> None:
    result = score_findings([])
    assert result.score == 0 and result.level == RiskLevel.LOW and result.evidence_strength == "none"


def test_score_is_bounded_to_100() -> None:
    findings = [f(f"R{i}", cat, 50, "high") for i, cat in enumerate(CATEGORY_CAPS)]
    result = score_findings(findings)
    assert 0 <= result.score <= 100
    assert result.score == 100


def test_negative_weights_are_clamped() -> None:
    assert score_findings([f("NEG", "urgency", -40)]).score == 0


def test_duplicate_rule_ids_counted_once() -> None:
    single = score_findings([f("A", "urgency", 10)]).score
    tripled = score_findings([f("A", "urgency", 10), f("A", "urgency", 10), f("A", "urgency", 10)])
    assert tripled.score == single
    assert tripled.findings[0].match_count == 3


def test_category_cap_and_diminishing_returns() -> None:
    result = score_findings([f("A", "urgency", 20), f("B", "urgency", 20), f("C", "urgency", 20)])
    # 20 + 10 + 10 = 40 raw, capped at 25
    assert result.score == CATEGORY_CAPS["urgency"]
    assert result.breakdown[0].raw == 40


def test_points_sum_matches_score() -> None:
    result = score_findings([f("A", "credential_request", 30, "high"), f("B", "urgency", 10), f("C", "url", 22)])
    assert round(sum(x.points for x in result.findings)) == result.score


def test_reproducible() -> None:
    findings = [f("A", "credential_request", 30, "high"), f("B", "urgency", 14), f("C", "payment_request", 18)]
    assert score_findings(copy.deepcopy(findings)).score == score_findings(copy.deepcopy(findings)).score


def test_evidence_strength_levels() -> None:
    assert score_findings([f("A", "urgency", 10, "low")]).evidence_strength == "limited"
    assert score_findings([f("A", "urgency", 10), f("B", "secrecy", 10)]).evidence_strength == "moderate"
    assert score_findings([f("A", "urgency", 10), f("B", "credential_request", 30, "high")]).evidence_strength == "strong"


def test_llm_and_classifier_contributions_are_capped() -> None:
    llm = [f(f"LLM_{i}", "llm", 5, "low", "llm") for i in range(8)]
    clf = [f("CLF", "classifier", 50, "low", "classifier")]
    result = score_findings(llm + clf)
    assert result.score <= CATEGORY_CAPS["llm"] + CATEGORY_CAPS["classifier"]
    assert result.level == RiskLevel.LOW  # model-only signals cannot reach MEDIUM on their own


def test_conflicting_signals_official_domain_plus_keywords_stay_low() -> None:
    findings = [f("URL_OFFICIAL_DOMAIN", "brand", 0, "info", "url_analyzer"),
                f("URL_SENSITIVE_KEYWORDS", "content", 8, "low", "url_analyzer")]
    assert score_findings(findings).level == RiskLevel.LOW


@pytest.mark.parametrize(("p", "points"), [(0.0, 0), (0.49, 0), (0.5, 0), (0.725, 6), (0.95, 12), (1.0, 12)])
def test_classifier_points(p: float, points: int) -> None:
    assert classifier_points(p) == points


def test_realistic_scam_scores_high_and_benign_low() -> None:
    scam = run_message_rules(normalize_text(
        "URGENT: Your account will be suspended within 24 hours. Verify your account and share the OTP sent "
        "to your phone. Do not tell anyone."))
    benign = run_message_rules(normalize_text("Hey, the meeting is at 3pm in room 4. Bring the slides."))
    assert score_findings(scam).level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert score_findings(benign).level == RiskLevel.LOW
