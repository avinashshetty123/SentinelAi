"""Turns a reputation report into bounded, explainable score evidence.

A malicious/suspicious verdict adds points (category "reputation", capped by the scoring engine).
A clean or missing report adds nothing and never lowers a score: absence of detections is not proof of safety.
"""

from __future__ import annotations

from app.schemas.scan import ReputationInfo
from app.services.detection.types import Finding


def reputation_findings(info: ReputationInfo, target: str | None = None) -> list[Finding]:
    if info.status != "ok" or info.provider is None:
        return []
    where = f" for {target}" if target else ""
    engines = ", ".join(e.engine for e in info.flagged_engines[:4])
    stats = info.stats
    if info.verdict == "malicious" and stats:
        weight = min(40, 20 + 5 * (stats.malicious - 1))
        return [
            Finding(
                rule_id="REP_VT_MALICIOUS",
                title=f"VirusTotal: {stats.malicious}/{stats.total} vendors flag as malicious",
                category="reputation",
                severity="high",
                source="reputation",
                weight=weight,
                explanation=f"Independent security vendors on VirusTotal classified this URL as malicious{where}. "
                "This is external threat-intelligence evidence, weighted by how many vendors agree.",
                evidence=f"Flagged by: {engines}" if engines else None,
            )
        ]
    if info.verdict == "suspicious" and stats:
        weight = min(20, 8 + 4 * (stats.suspicious - 1))
        return [
            Finding(
                rule_id="REP_VT_SUSPICIOUS",
                title=f"VirusTotal: {stats.suspicious}/{stats.total} vendors flag as suspicious",
                category="reputation",
                severity="medium",
                source="reputation",
                weight=weight,
                explanation=f"Some security vendors on VirusTotal consider this URL suspicious{where}. Weaker than a "
                "malicious verdict, but meaningful alongside other signals.",
                evidence=f"Flagged by: {engines}" if engines else None,
            )
        ]
    if info.verdict == "clean":
        return [
            Finding(
                rule_id="REP_VT_CLEAN",
                title="VirusTotal: no vendor flags this URL",
                category="reputation",
                severity="info",
                source="reputation",
                weight=0,
                explanation="No VirusTotal vendor flagged this URL. This does not lower the score — brand-new phishing "
                "links are often clean until reported.",
            )
        ]
    if info.verdict == "not_found":
        return [
            Finding(
                rule_id="REP_VT_UNKNOWN",
                title="VirusTotal: no report for this URL",
                category="reputation",
                severity="info",
                source="reputation",
                weight=0,
                explanation="VirusTotal has never seen this exact URL. Treat it as unknown, not safe.",
            )
        ]
    return []
