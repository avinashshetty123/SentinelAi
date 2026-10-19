"""Deterministic social-engineering indicators for messages.

Each rule is an *indicator*, not proof. Weights are documented in docs/ARCHITECTURE.md and combined by
the scoring engine with per-category caps and diminishing returns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.detection.text import NormalizedText, excerpt
from app.services.detection.types import Finding, Severity

RULE_VERSION = "msg-rules-1.0"

_NEGATION = re.compile(
    r"\b(never|not|don'?t|do not|won'?t|will not|no one|nobody|cannot|can'?t)\b[^.!?\n]{0,25}$", re.IGNORECASE
)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    severity: Severity
    weight: int
    patterns: tuple[str, ...]
    explanation: str
    negation_guard: bool = False  # skip matches preceded by "never/do not …" (e.g. "never share your OTP")

    def compiled(self) -> list[re.Pattern[str]]:
        return [re.compile(p, re.IGNORECASE) for p in self.patterns]


_VERB_GIVE = r"(?:share|send|tell|give|provide|forward|reply\s+with|enter|type|confirm|submit|read\s+out|disclose)"
_CURRENCY = r"(?:\$|€|£|₹|rs\.?|inr|usd|eur|gbp|rupees?|dollars?)"

RULES: tuple[Rule, ...] = (
    Rule(
        "MSG_URGENCY_PRESSURE",
        "Time pressure",
        "urgency",
        "low",
        10,
        (
            r"\burgent(ly)?\b",
            r"\bimmediate(ly)?\b",
            r"\bwithin\s+\d+\s*(hours?|hrs?|minutes?|mins?)\b",
            r"\bact\s+now\b",
            r"\bfinal\s+(notice|warning|reminder)\b",
            r"\blast\s+chance\b",
            r"\bexpir(es|ing)\s+(today|soon|tonight|in)\b",
            r"\btoday\s+only\b",
            r"\basap\b",
            r"\bbefore\s+it'?s\s+too\s+late\b",
        ),
        "The message pushes you to act quickly. Pressure discourages careful verification; genuine "
        "organisations rarely require instant action through a message.",
    ),
    Rule(
        "MSG_URGENCY_THREAT",
        "Threat of loss or penalty",
        "urgency",
        "medium",
        14,
        (
            r"\b(account|card|service|number|sim|wallet|profile|access)\s+(will\s+be|has\s+been|is|got)\s+"
            r"(suspended|blocked|locked|terminated|deactivated|closed|disabled|frozen|restricted)\b",
            r"\blegal\s+action\b",
            r"\barrest(\s+warrant)?\b",
            r"\bpenalt(y|ies)\b",
            r"\blawsuit\b",
            r"\bpermanently\s+(blocked|deleted|suspended)\b",
        ),
        "The message threatens suspension, penalties or legal consequences. Fear is a common lever used "
        "to override caution.",
    ),
    Rule(
        "MSG_CREDENTIAL_OTP",
        "Request for a one-time code",
        "credential_request",
        "high",
        30,
        (
            _VERB_GIVE + r"[^.!?\n]{0,30}\b(otp|one[- ]time\s+(pass(word|code)?|pin|code)|verification\s+code|"
            r"security\s+code|auth(entication)?\s+code|2fa\s+code|login\s+code)\b",
        ),
        "The message asks you to share a one-time or verification code. These codes authorise logins and "
        "payments; legitimate services never ask you to send them to anyone.",
        negation_guard=True,
    ),
    Rule(
        "MSG_CREDENTIAL_SECRET",
        "Request for passwords, PINs or card data",
        "credential_request",
        "high",
        28,
        (
            _VERB_GIVE + r"[^.!?\n]{0,30}\b(password|passcode|pin\b|cvv|cvc|card\s+(number|details)|"
            r"login\s+(details|credentials)|credentials|net\s?banking|upi\s+pin|security\s+answer|seed\s+phrase|"
            r"recovery\s+phrase|private\s+key)",
        ),
        "The message asks for secret credentials or card details. No genuine bank, employer or support "
        "team will ask for these through a message.",
        negation_guard=True,
    ),
    Rule(
        "MSG_CREDENTIAL_VERIFY",
        "Account verification request",
        "credential_request",
        "medium",
        16,
        (
            r"\b(verify|confirm|update|validate|reactivate|unlock|restore|re-?activate)\s+(your\s+)?"
            r"(account|identity|details|information|kyc|payment\s+(method|details)|billing(\s+info)?|"
            r"bank\s+details|card)\b",
        ),
        "The message asks you to verify or update account details, often via a link. This is the most "
        "common lead-in to credential phishing.",
        negation_guard=True,
    ),
    Rule(
        "MSG_PAYMENT_FEE",
        "Request to pay a fee or transfer money",
        "payment_request",
        "medium",
        18,
        (
            r"\b(pay|transfer|deposit|send|remit)\b[^.!?\n]{0,40}(\bfee\b|\bcharges?\b|" + _CURRENCY + r")",
            r"\b(processing|registration|release|clearance|customs|delivery|redelivery|activation|training|"
            r"security|verification|unlock|handling|joining)\s+(fee|charges?)\b",
            r"\brefundable\s+deposit\b",
        ),
        "The message requests a payment or fee. Unexpected fees to release a parcel, prize, job or refund "
        "are a hallmark of advance-fee fraud.",
    ),
    Rule(
        "MSG_PAYMENT_UNUSUAL",
        "Untraceable payment method",
        "payment_request",
        "high",
        20,
        (
            r"\bgift\s?cards?\b",
            r"\b(bitcoin|btc|crypto(currency)?|usdt|tether|ethereum)\b",
            r"\bwire\s+transfer\b",
            r"\bwestern\s+union\b",
            r"\bmoneygram\b",
            r"\b(itunes|google\s+play|steam|amazon)\s+(gift\s+)?(card|code|voucher)s?\b",
        ),
        "The message mentions gift cards, cryptocurrency or wire services. These are hard to reverse and "
        "are preferred by scammers.",
    ),
    Rule(
        "MSG_PAYMENT_COLLECT",
        "Approve-to-receive payment trick",
        "payment_request",
        "medium",
        14,
        (
            r"\b(scan|approve|accept)\b[^.!?\n]{0,25}\b(qr(\s+code)?|collect\s+request|payment\s+request|"
            r"upi\s+request)\b",
            r"\b(enter|use)\s+(your\s+)?(upi\s+)?pin\s+to\s+receive\b",
        ),
        "You are asked to scan a QR code or approve a request in order to *receive* money. In real payment "
        "apps, approving or entering a PIN sends money out.",
    ),
    Rule(
        "MSG_IMPERSONATION_AUTHORITY",
        "Claims to be an authority",
        "impersonation",
        "low",
        8,
        (
            r"\b(irs|hmrc|income\s+tax\s+department|tax\s+department|customs\s+(department|office)|police|"
            r"cyber\s?(crime\s+)?cell|fbi|ministry|rbi|sebi|trai|court|government\s+of)\b",
        ),
        "The message invokes a government, tax, police or regulatory body. Impersonating authorities lends "
        "false legitimacy; such bodies rarely initiate contact by SMS or chat.",
    ),
    Rule(
        "MSG_IMPERSONATION_BRAND",
        "Claims to be a well-known company's support",
        "impersonation",
        "low",
        8,
        (
            r"\b(paypal|amazon|apple|microsoft|netflix|google|meta|facebook|whatsapp|instagram|fedex|dhl|ups|usps|"
            r"royal\s+mail|india\s+post|sbi|hdfc|icici|axis\s+bank|chase|wells\s+fargo|bank\s+of\s+america|"
            r"coinbase|binance|paytm|phonepe)\b[^.!?\n]{0,20}\b(support|security|team|department|customer\s+care|"
            r"helpdesk|service\s+desk|fraud\s+(team|department)|account\s+team)\b",
            r"\bdear\s+(customer|user|valued\s+customer|account\s+holder|client|sir\s*/\s*madam)\b",
        ),
        "The message presents itself as a company's support/security team or uses a generic greeting. "
        "Real providers usually address you by name and do not ask for sensitive actions via message.",
    ),
    Rule(
        "MSG_REWARD_LURE",
        "Prize, lottery or reward lure",
        "reward_lure",
        "medium",
        18,
        (
            r"\byou('ve|\s+have)?\s+(won|been\s+selected|are\s+(a\s+)?(lucky\s+)?winner)\b",
            r"\b(lottery|jackpot|lucky\s+draw|sweepstakes?)\b",
            r"\bclaim\s+(your|the|this)\s+(prize|reward|gift|refund|cashback|bonus|winnings)\b",
            r"\bcongratulations\b[^.!?\n]{0,40}\b(won|winner|selected|reward|prize)\b",
        ),
        "The message promises an unexpected prize, refund or reward. Unsolicited winnings are a classic lure "
        "for collecting fees or personal data.",
    ),
    Rule(
        "MSG_UNREALISTIC_RETURN",
        "Unrealistic returns or income",
        "reward_lure",
        "medium",
        18,
        (
            r"\b(guaranteed|assured|risk[- ]free|fixed)\s+(returns?|profits?|income|earnings)\b",
            r"\bdouble\s+your\s+(money|investment|crypto)\b",
            r"\b\d{1,3}\s?%\s+(daily|weekly|monthly)\s+(returns?|profits?|interest)\b",
            r"\bearn\s+" + _CURRENCY + r"?\s?\d[\d,]*\s*" + _CURRENCY + r"?\s+(per|a|every|each)\s+"
            r"(day|hour|week|task)\b",
        ),
        "The message promises guaranteed or very high returns. Legitimate investments and jobs do not "
        "guarantee large, fast profits.",
    ),
    Rule(
        "MSG_JOB_SCAM",
        "Too-easy job offer pattern",
        "job_scam",
        "medium",
        14,
        (
            r"\b(work\s+from\s+home|part[- ]time\s+(job|work)|online\s+job|data\s+entry\s+job|task[- ]based\s+job)\b",
            r"\blike\s+(and|&)\s+subscribe\b",
            r"\b(youtube|instagram)\s+(likes|tasks)\b",
            r"\bno\s+(experience|interview|qualification)s?\s+(needed|required)\b",
            r"\b(hired|selected|shortlisted)\b[^.!?\n]{0,40}\b(telegram|whatsapp)\b",
        ),
        "The message has features of task or job scams: easy money, no interview, contact via chat apps. "
        "These often end in requests for a 'deposit' or 'training fee'.",
    ),
    Rule(
        "MSG_SECRECY",
        "Asks you to keep it secret",
        "secrecy",
        "medium",
        14,
        (
            r"\b(do\s+not|don'?t|dont)\s+(tell|inform|share\s+this\s+with|disclose\s+this\s+to)\s+(anyone|anybody|"
            r"your\s+(family|bank|parents|friends))\b",
            r"\bkeep\s+(this|it)\s+(confidential|secret|private|between\s+us)\b",
            r"\b(do\s+not|don'?t)\s+(contact|call|visit)\s+(the\s+|your\s+)?(bank|branch|police)\b",
        ),
        "The message asks you to keep the request secret. Isolating the target from people who might spot "
        "the scam is a common manipulation tactic.",
    ),
    Rule(
        "MSG_VERIFICATION_BYPASS",
        "Steers you away from official channels",
        "verification_bypass",
        "medium",
        16,
        (
            r"\b(ignore|disregard|skip|bypass)\b[^.!?\n]{0,20}\b(official|bank|normal|usual|standard)\s+"
            r"(process|channel|procedure|app|website)\b",
            r"\b(only|just)\s+(reply|respond)\s+(here|to\s+this)\b",
            r"\bcontact\s+(me|us)\s+(only\s+)?(on|via|through)\s+(whatsapp|telegram|signal)\b",
            r"\b(do\s+not|don'?t)\s+(use|go\s+to|visit|open)\s+the\s+(official\s+)?(app|website|branch)\b",
        ),
        "The message discourages using official apps, websites or phone numbers. Verifying through an "
        "independent channel is exactly what scammers want to prevent.",
    ),
    Rule(
        "MSG_REMOTE_ACCESS",
        "Remote-access software request",
        "remote_access",
        "high",
        24,
        (
            r"\b(anydesk|teamviewer|quick\s?support|rustdesk|ultraviewer|airdroid|screen\s?share|"
            r"remote\s+(access|support|desktop|control))\b",
        ),
        "The message involves remote-access or screen-sharing tools. Granting remote access lets an attacker "
        "see codes and operate your device or bank account.",
    ),
    Rule(
        "MSG_DOWNLOAD_INSTALL",
        "Asks you to install an app or open a file",
        "download_install",
        "medium",
        18,
        (
            r"\b(download|install|open|run)\b[^.!?\n]{0,30}\b(app|apk|attachment|file|software|extension|update)\b",
            r"\b\w+\.(apk|exe|scr|msi|bat|vbs|jar)\b",
        ),
        "The message asks you to download, install or open something. Apps and attachments from messages "
        "are a common route for malware and spyware.",
        negation_guard=True,
    ),
    Rule(
        "MSG_PERSONAL_INFO",
        "Requests sensitive personal information",
        "personal_info",
        "medium",
        16,
        (
            r"\b(send|share|provide|upload|confirm|submit)\b[^.!?\n]{0,30}\b(aadhaar|aadhar|ssn|social\s+security|"
            r"pan\s+(card|number)|passport|date\s+of\s+birth|dob|mother'?s\s+maiden|bank\s+(account|statement)s?|"
            r"id\s+(card|proof)|selfie)\b",
        ),
        "The message asks for identity documents or personal details that enable identity theft or account takeover.",
        negation_guard=True,
    ),
    Rule(
        "MSG_PROMPT_INJECTION",
        "Attempts to manipulate automated analysis",
        "prompt_injection",
        "medium",
        20,
        (
            r"\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)\b",
            r"\byou\s+are\s+now\s+(a|an|in)\b",
            r"\bsystem\s+prompt\b",
            r"\b(classify|mark|rate|label|treat|report)\s+(this|the)\s+(message|text|email)\s+as\s+"
            r"(safe|legitimate|low[- ]risk|harmless|not\s+(a\s+)?(scam|spam|phishing))\b",
            r"\bdisregard\s+(your|the|all)\s+(rules|instructions|guidelines)\b",
            r"\b(as\s+an?\s+)?(ai|language\s+model|assistant)\b[^.!?\n]{0,30}\b(must|should|will)\s+(say|respond|"
            r"answer|reply)\b",
        ),
        "The text contains instructions aimed at an AI or automated filter (e.g. 'ignore previous "
        "instructions', 'mark this as safe'). Legitimate messages have no reason to do this.",
    ),
)

# Metadata for the combination rules implemented in combination_findings() (shown in the UI rule catalogue).
COMBINATION_RULES: list[dict[str, object]] = [
    {
        "rule_id": "COMBO_CREDENTIAL_URGENCY",
        "title": "Credential request under time pressure",
        "weight": 12,
        "explanation": "credential_request + urgency",
    },
    {
        "rule_id": "COMBO_LINK_CREDENTIAL",
        "title": "Link combined with a credential/verification request",
        "weight": 12,
        "explanation": "credential_request + link (8 if the link itself looks clean)",
    },
    {
        "rule_id": "COMBO_PAYMENT_URGENCY",
        "title": "Payment demand under time pressure",
        "weight": 8,
        "explanation": "payment_request + urgency",
    },
    {
        "rule_id": "COMBO_IMPERSONATION_REQUEST",
        "title": "Claimed authority/brand asking for sensitive action",
        "weight": 10,
        "explanation": "impersonation + credential/payment/personal-info request",
    },
    {
        "rule_id": "COMBO_ADVANCE_FEE",
        "title": "Reward or job that requires paying first",
        "weight": 14,
        "explanation": "reward_lure or job_scam + payment_request",
    },
    {
        "rule_id": "COMBO_REMOTE_ACCESS_SUPPORT",
        "title": "Remote access combined with support or payment pretext",
        "weight": 12,
        "explanation": "remote_access + credential/payment/impersonation",
    },
]
for _c in COMBINATION_RULES:
    _c.update(category="combination", severity="high")

_COMPILED: list[tuple[Rule, list[re.Pattern[str]]]] = [(r, r.compiled()) for r in RULES]


def _negated(text: str, start: int) -> bool:
    window = text[max(0, start - 40) : start]
    return bool(_NEGATION.search(window))


def run_message_rules(normalized: NormalizedText) -> list[Finding]:
    text = normalized.text
    findings: list[Finding] = []
    for rule, patterns in _COMPILED:
        first_span: tuple[int, int] | None = None
        count = 0
        spans: list[tuple[int, int]] = []
        for pattern in patterns:
            for match in pattern.finditer(text):
                if rule.negation_guard and _negated(text, match.start()):
                    continue
                count += 1
                if len(spans) < 10:
                    spans.append(match.span())
                if first_span is None:
                    first_span = match.span()
        if first_span is None:
            continue
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                title=rule.title,
                category=rule.category,
                severity=rule.severity,
                source="rule",
                weight=rule.weight,
                explanation=rule.explanation,
                evidence=excerpt(text, *first_span),
                match_count=count,
                spans=spans,
            )
        )

    if normalized.invisible_char_count or normalized.mixed_script_tokens:
        parts = []
        if normalized.invisible_char_count:
            parts.append(f"{normalized.invisible_char_count} invisible character(s)")
        if normalized.mixed_script_tokens:
            parts.append("words mixing alphabets: " + ", ".join(normalized.mixed_script_tokens[:3]))
        findings.append(
            Finding(
                rule_id="MSG_OBFUSCATION",
                title="Hidden or disguised characters",
                category="obfuscation",
                severity="medium",
                source="rule",
                weight=12,
                explanation="The text contains zero-width/bidirectional control characters or words that mix "
                "lookalike letters from different alphabets. These are used to evade filters and "
                "imitate trusted names.",
                evidence="; ".join(parts),
            )
        )
    return findings


def combination_findings(findings: list[Finding], url_count: int) -> list[Finding]:
    cats = {f.category for f in findings if f.source in ("rule", "url_analyzer")}
    has_risky_url = any(f.source == "url_analyzer" and f.weight >= 10 for f in findings)
    combos: list[Finding] = []

    def add(rule_id: str, title: str, weight: int, explanation: str) -> None:
        combos.append(
            Finding(
                rule_id=rule_id,
                title=title,
                category="combination",
                severity="high",
                source="combination",
                weight=weight,
                explanation=explanation,
            )
        )

    if "credential_request" in cats and "urgency" in cats:
        add(
            "COMBO_CREDENTIAL_URGENCY",
            "Credential request under time pressure",
            12,
            "A request for codes, passwords or verification combined with urgency is the typical structure "
            "of an account-takeover attempt.",
        )
    if "credential_request" in cats and (url_count > 0):
        add(
            "COMBO_LINK_CREDENTIAL",
            "Link combined with a credential/verification request",
            12 if has_risky_url else 8,
            "The message asks you to verify or provide credentials and includes a link, the standard pattern "
            "of credential phishing.",
        )
    if "payment_request" in cats and "urgency" in cats:
        add(
            "COMBO_PAYMENT_URGENCY",
            "Payment demand under time pressure",
            8,
            "Combining a payment request with a deadline or threat is common in invoice, fine and delivery scams.",
        )
    if "impersonation" in cats and ({"credential_request", "payment_request", "personal_info"} & cats):
        add(
            "COMBO_IMPERSONATION_REQUEST",
            "Claimed authority/brand asking for sensitive action",
            10,
            "The sender claims to be a trusted organisation and asks for credentials, payment or personal data.",
        )
    if ({"reward_lure", "job_scam"} & cats) and "payment_request" in cats:
        add(
            "COMBO_ADVANCE_FEE",
            "Reward or job that requires paying first",
            14,
            "A prize, refund or job that requires you to pay a fee first is the defining pattern of advance-fee fraud.",
        )
    if "remote_access" in cats and ({"credential_request", "payment_request", "impersonation"} & cats):
        add(
            "COMBO_REMOTE_ACCESS_SUPPORT",
            "Remote access combined with support or payment pretext",
            12,
            "Remote-access tools combined with a support, refund or payment story are the core of tech-support "
            "and refund scams.",
        )
    return combos
