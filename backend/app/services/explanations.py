"""Deterministic, template-based explanations. Used always for the stored summary, and as the fallback
when the LLM is unavailable. Never presented as AI output."""

from __future__ import annotations

from app.models.enums import RiskLevel
from app.services.detection.types import Finding

CATEGORY_LABELS = {
    "credential_request": "requests for codes, passwords or account verification",
    "payment_request": "payment or fee requests",
    "urgency": "pressure or threats",
    "impersonation": "claims to represent a trusted organisation",
    "reward_lure": "prize, refund or unrealistic-return lures",
    "job_scam": "too-good-to-be-true job patterns",
    "secrecy": "requests for secrecy",
    "verification_bypass": "steering away from official channels",
    "remote_access": "remote-access tool requests",
    "download_install": "requests to install apps or open files",
    "personal_info": "requests for identity documents or personal data",
    "prompt_injection": "attempts to manipulate automated analysis",
    "obfuscation": "hidden or disguised characters",
    "url": "suspicious link characteristics",
    "classifier": "spam-like wording (statistical model)",
    "llm": "AI-identified social-engineering cues",
    "combination": "a combination of related warning signs",
    "transport": "an unencrypted connection",
    "deception": "address tricks that disguise the destination",
    "host": "unusual host characteristics",
    "brand": "brand imitation",
    "redirection": "hidden or redirected destinations",
    "content": "sign-in, payment or download wording",
    "reputation": "security-vendor detections on VirusTotal",
    "authentication": "failed sender authentication (SPF/DKIM/DMARC)",
    "sender_mismatch": "a sender identity that doesn't add up",
    "relay": "an unusual delivery path",
}

RECOMMENDATIONS = {
    "credential_request": "Do not share one-time codes, passwords, PINs or card details. No legitimate "
    "organisation asks for them by message.",
    "payment_request": "Do not pay. Verify any invoice, fine or fee through the organisation's official "
    "website or a phone number you look up yourself.",
    "urgency": "Pause before acting: genuine organisations give you time to verify a request.",
    "impersonation": "Contact the organisation through its official app, website or a number from your card "
    "or statement — not through details in this message.",
    "reward_lure": "Treat unexpected prizes, refunds or guaranteed returns as suspicious, especially if a "
    "fee is required.",
    "job_scam": "Research the employer independently. Legitimate employers do not charge fees to hire you.",
    "secrecy": "Talk to someone you trust; requests for secrecy are a warning sign.",
    "verification_bypass": "Always use official channels you find yourself to confirm requests.",
    "remote_access": "Do not install remote-access apps or share your screen at a stranger's request.",
    "download_install": "Do not install apps or open attachments from unsolicited messages; use official app stores.",
    "personal_info": "Do not send identity documents or personal details in reply to a message.",
    "prompt_injection": "Treat text that tries to instruct automated filters as a strong warning sign.",
    "url": "Do not open the link. If you need the service, type its official address yourself.",
    "deception": "Do not open the link; its address is constructed to disguise where it leads.",
    "brand": "Navigate to the brand's official site directly instead of using this link.",
    "redirection": "Avoid shortened or redirecting links from unknown senders; the destination is hidden.",
    "transport": "Never enter passwords or payment details on pages without HTTPS.",
    "host": "Be cautious with links to raw IP addresses or unusual hosts.",
    "content": "Do not download files or sign in through this link.",
    "reputation": "Security vendors have flagged this link. Do not open it, and warn others who received it.",
    "authentication": "Treat the sender as unverified: contact the organisation through a channel you look up "
    "yourself.",
    "sender_mismatch": "Do not reply: replies or the real sender address point somewhere other than who it claims "
    "to be.",
}

GENERIC_RECOMMENDATIONS = [
    "If you already shared a code, password or payment details, contact your bank or provider immediately "
    "using official contact details and change affected passwords.",
    "Report the message to your provider, carrier or national cyber-crime reporting service.",
]

BASE_LIMITATIONS_MESSAGE = [
    "Indicators are risk signals, not proof. Legitimate messages can contain urgency or links, and scams "
    "can avoid every known indicator.",
    "The sender's identity was not verified and no links were visited.",
    "The risk score is an evidence index from 0–100, not a probability of fraud.",
]

BASE_LIMITATIONS_URL = [
    "Analysis uses only the URL text. The site was not visited, DNS was not resolved and no live reputation "
    "lookup was performed.",
    "A clean result does not mean a URL is safe; a high score does not confirm phishing or malware.",
    "The risk score is an evidence index from 0–100, not a probability of maliciousness.",
]


def _top_categories(findings: list[Finding], limit: int = 3) -> list[str]:
    seen: list[str] = []
    for f in sorted(findings, key=lambda x: -x.points):
        if f.points <= 0 or f.category in seen or f.category in ("combination", "classifier", "llm"):
            continue
        seen.append(f.category)
        if len(seen) >= limit:
            break
    return seen


def build_summary(kind: str, level: RiskLevel, score: int, findings: list[Finding]) -> str:
    noun = {"message": "message", "url": "URL", "email": "e-mail"}.get(kind, kind)
    cats = _top_categories(findings)
    if not cats:
        if score == 0:
            return (
                f"No known risk indicators were found in this {noun}. This does not guarantee it is safe — "
                "stay cautious with unexpected requests."
            )
        return f"Only weak signals were found in this {noun} (score {score}/100). Treat it with ordinary caution."
    described = ", ".join(CATEGORY_LABELS.get(c, c) for c in cats)
    lead = {
        RiskLevel.LOW: f"This {noun} shows few risk indicators",
        RiskLevel.MEDIUM: f"This {noun} shows some warning signs",
        RiskLevel.HIGH: f"This {noun} shows several strong warning signs",
        RiskLevel.CRITICAL: f"This {noun} matches multiple high-risk scam patterns",
    }[level]
    return f"{lead} (score {score}/100, {level.value}): {described}."


def build_recommendations(level: RiskLevel, findings: list[Finding], limit: int = 5) -> list[str]:
    recs: list[str] = []
    for cat in _top_categories(findings, limit=4):
        rec = RECOMMENDATIONS.get(cat)
        if rec and rec not in recs:
            recs.append(rec)
    if level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        recs.extend(GENERIC_RECOMMENDATIONS)
    elif not recs:
        recs.append("No specific action is required, but verify unexpected requests through official channels.")
    return recs[:limit]
