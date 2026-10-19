from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["info", "low", "medium", "high"]
FindingSource = Literal["rule", "url_analyzer", "classifier", "llm", "combination"]


@dataclass
class Finding:
    """One piece of evidence. `weight` is the documented rule weight; `points` is the score contribution
    after category caps and diminishing returns are applied by the scoring engine."""

    rule_id: str
    title: str
    category: str
    severity: Severity
    source: FindingSource
    weight: int
    explanation: str
    evidence: str | None = None
    match_count: int = 1
    points: float = 0.0
    corroborated_by: list[str] = field(default_factory=list)
