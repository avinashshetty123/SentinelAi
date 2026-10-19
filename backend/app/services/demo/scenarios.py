"""Predefined attack-replay scenarios.

Messages are written to trigger real detection rules — the same rules that fire on genuine scam
messages. Links use RFC 2606 reserved names (.example) and RFC 5737 documentation addresses
(203.0.113.0/24) so they can never resolve to real infrastructure and are never visited.
Records are tagged DataSource.DEMO so they can be reset without touching application data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from app.models.enums import ContentType, EventType, RiskLevel

StepKind = Literal["message_scan", "url_scan", "sim_event", "create_incident", "note"]


@dataclass(frozen=True)
class ScenarioStep:
    kind: StepKind
    title: str
    text: str = ""
    content_type: ContentType = ContentType.AUTO
    url: str = ""
    event_type: EventType | None = None
    severity: RiskLevel = RiskLevel.MEDIUM
    description: str = ""
    actor: str = "synthetic-user-001"


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    description: str
    expected_outcome: str
    incident_title: str
    steps: tuple[ScenarioStep, ...] = field(default_factory=tuple)


SCENARIOS: dict[str, Scenario] = {
    s.id: s
    for s in (
        Scenario(
            id="payment-scam",
            title="Fake invoice payment scam",
            description=(
                "An SMS impersonates a billing department, invents an overdue invoice, threatens "
                "account suspension within 24 hours, and pushes a payment link hosted on a raw IP "
                "address with a non-standard port — a classic advance-fee / credential-harvest combo."
            ),
            expected_outcome=(
                "Message scored HIGH/CRITICAL, URL flagged for raw-IP + unusual port, events broadcast, "
                "incident opened."
            ),
            incident_title="[DEMO] Invoice payment scam — synthetic-user-001",
            steps=(
                ScenarioStep(
                    kind="message_scan",
                    title="Analyze suspicious payment SMS",
                    content_type=ContentType.PAYMENT_REQUEST,
                    text=(
                        "URGENT: Your account will be suspended within 24 hours due to an unpaid "
                        "invoice of Rs 4,999. To avoid service interruption, pay the clearance fee "
                        "immediately at http://203.0.113.24:8080/secure-billing/verify and confirm "
                        "your card details and OTP. Do NOT contact your bank — this is handled "
                        "exclusively by our billing department. Reply STOP to opt out."
                    ),
                ),
                ScenarioStep(
                    kind="url_scan",
                    title="Analyze the embedded payment link",
                    url="http://203.0.113.24:8080/secure-billing/verify",
                ),
                ScenarioStep(kind="create_incident", title="Open incident and link evidence"),
                ScenarioStep(
                    kind="note",
                    title="Add analyst triage note",
                    description=(
                        "Triage: raw IP 203.0.113.24 on port 8080 has no legitimate billing use. "
                        "Payment pressure + OTP request + secrecy instruction = high-confidence "
                        "advance-fee scam. Recommend block-listing the IP and issuing a user advisory."
                    ),
                ),
            ),
        ),
        Scenario(
            id="job-offer-scam",
            title="Task-based job offer with advance fee",
            description=(
                "A WhatsApp-style message offers easy remote income for liking YouTube videos, "
                "demands a 'refundable registration fee' via UPI, moves the conversation to Telegram "
                "to avoid platform moderation, and links to a typosquatted careers domain."
            ),
            expected_outcome=(
                "Advance-fee + secrecy combination detected; lookalike careers URL flagged; incident opened."
            ),
            incident_title="[DEMO] Advance-fee job scam — synthetic-user-002",
            steps=(
                ScenarioStep(
                    kind="message_scan",
                    title="Analyze job offer message",
                    content_type=ContentType.JOB_OFFER,
                    text=(
                        "Congratulations! You have been selected for a flexible part-time opportunity: "
                        "complete simple tasks (like and subscribe to YouTube videos) and earn "
                        "Rs 3,000–5,000 per day from home. No experience required. "
                        "To activate your account, pay a fully refundable registration fee of "
                        "Rs 1,500 via UPI to tasks.pay@upi. Do not discuss this offer with anyone "
                        "until your account is verified — contact your assigned manager only on "
                        "Telegram @taskmanager99. Register now: "
                        "https://linkedln-careers.example/onboarding/verify"
                    ),
                ),
                ScenarioStep(
                    kind="url_scan",
                    title="Analyze onboarding link",
                    url="https://linkedln-careers.example/onboarding/verify",
                ),
                ScenarioStep(kind="create_incident", title="Open incident and link evidence"),
                ScenarioStep(
                    kind="note",
                    title="Add analyst triage note",
                    description=(
                        "Triage: 'linkedln-careers.example' is a typosquat of linkedin.com. "
                        "Advance fee + secrecy instruction + off-platform redirect = textbook "
                        "task-scam pattern. No legitimate employer charges a registration fee."
                    ),
                ),
            ),
        ),
        Scenario(
            id="account-takeover",
            title="Phishing-led account takeover",
            description=(
                "A password-reset SMS impersonates Microsoft Security, embeds a brand-in-subdomain "
                "phishing URL, and requests the victim's OTP. The pipeline then simulates the "
                "resulting failed-login burst, a suspicious successful login from a new device, "
                "and an account-takeover warning — showing the full attack chain from initial "
                "phishing message to post-compromise detection."
            ),
            expected_outcome=(
                "Phishing SMS flagged CRITICAL; three correlated security events broadcast live; "
                "incident opened with complete attack-chain timeline."
            ),
            incident_title="[DEMO] Phishing-led account takeover — synthetic-user-007",
            steps=(
                ScenarioStep(
                    kind="message_scan",
                    title="Analyze phishing password-reset SMS",
                    content_type=ContentType.ACCOUNT_VERIFICATION,
                    text=(
                        "Microsoft Security Alert: We detected an unusual sign-in attempt on your "
                        "account from a new device in Chennai, India. Your account will be locked "
                        "in 2 hours if you do not verify your identity. "
                        "Verify now: http://microsoft.com.account-security.example/login "
                        "Enter the 6-digit verification code we just sent to your registered "
                        "mobile number. Do not share this code with anyone, including Microsoft support."
                    ),
                ),
                ScenarioStep(
                    kind="sim_event",
                    title="Simulate failed-login burst",
                    event_type=EventType.FAILED_LOGIN_BURST,
                    severity=RiskLevel.MEDIUM,
                    actor="synthetic-user-007",
                    description=(
                        "14 failed sign-in attempts in 3 minutes for synthetic-user-007 "
                        "from 203.0.113.77 — consistent with credential-stuffing after phishing."
                    ),
                ),
                ScenarioStep(
                    kind="sim_event",
                    title="Simulate suspicious successful login",
                    event_type=EventType.SUSPICIOUS_LOGIN,
                    severity=RiskLevel.HIGH,
                    actor="synthetic-user-007",
                    description=(
                        "Successful sign-in for synthetic-user-007 from an unrecognized device "
                        "and location immediately following the failed-login burst."
                    ),
                ),
                ScenarioStep(
                    kind="sim_event",
                    title="Raise account-takeover warning",
                    event_type=EventType.ACCOUNT_TAKEOVER_WARNING,
                    severity=RiskLevel.CRITICAL,
                    actor="synthetic-user-007",
                    description=(
                        "Possible account takeover: recovery e-mail change requested within "
                        "4 minutes of the suspicious login for synthetic-user-007."
                    ),
                ),
                ScenarioStep(kind="create_incident", title="Open incident and link full attack chain"),
                ScenarioStep(
                    kind="note",
                    title="Add analyst triage note",
                    description=(
                        "Triage: brand-in-subdomain URL (microsoft.com.account-security.example) "
                        "is a classic phishing pattern. Correlated events confirm the victim "
                        "likely clicked. Recommend immediate password reset, session revocation "
                        "and MFA enforcement."
                    ),
                ),
            ),
        ),
    )
}
