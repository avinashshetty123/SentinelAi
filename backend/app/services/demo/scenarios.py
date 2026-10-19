"""Predefined, clearly synthetic attack-replay scenarios.

All content is synthetic. URLs use reserved documentation names/addresses (RFC 2606 `.example`,
RFC 5737 203.0.113.0/24) so they cannot point at real infrastructure, and they are never visited.
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
            description="A synthetic SMS claims an unpaid invoice will trigger account suspension and pushes a "
            "payment link on a raw IP address.",
            expected_outcome="Message scored HIGH/CRITICAL, URL flagged, events broadcast, incident opened.",
            incident_title="[DEMO] Invoice payment scam targeting synthetic-user-001",
            steps=(
                ScenarioStep(
                    kind="message_scan",
                    title="Analyze suspicious payment SMS",
                    content_type=ContentType.PAYMENT_REQUEST,
                    text="[SYNTHETIC DEMO] URGENT: Your account will be suspended within 24 hours due to an "
                    "unpaid invoice of Rs 4,999. Pay the clearance fee immediately at "
                    "http://203.0.113.24:8080/secure-billing/verify and confirm your card details. "
                    "Do not contact the bank, this is handled by our billing department only.",
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
                    description="Triage: synthetic target did not click. Block-list the IP in the demo "
                    "environment and warn users about invoice-themed SMS.",
                ),
            ),
        ),
        Scenario(
            id="job-offer-scam",
            title="Task-based job offer with joining fee",
            description="A synthetic chat message offers easy remote income, moves the conversation to Telegram "
            "and demands a refundable 'registration fee'.",
            expected_outcome="Advance-fee combination detected; lookalike careers URL flagged; incident opened.",
            incident_title="[DEMO] Advance-fee job scam",
            steps=(
                ScenarioStep(
                    kind="message_scan",
                    title="Analyze job offer message",
                    content_type=ContentType.JOB_OFFER,
                    text="[SYNTHETIC DEMO] Congratulations! You have been selected for a part-time job: like and "
                    "subscribe to YouTube videos and earn Rs 3,000 per day. No experience needed. Pay a "
                    "refundable registration fee of Rs 1,500 via UPI to activate your account. Contact us "
                    "only on Telegram. Register at https://linkedln-careers.example/onboarding/verify",
                ),
                ScenarioStep(
                    kind="url_scan",
                    title="Analyze onboarding link",
                    url="https://linkedln-careers.example/onboarding/verify",
                ),
                ScenarioStep(kind="create_incident", title="Open incident and link evidence"),
            ),
        ),
        Scenario(
            id="account-takeover",
            title="Phishing-led account takeover",
            description="A synthetic password-reset phishing SMS is followed by simulated failed logins, a login "
            "from a new location, and an account-takeover warning.",
            expected_outcome="Phishing SMS flagged; three simulation events broadcast; incident opened with a "
            "complete timeline.",
            incident_title="[DEMO] Suspected account takeover of synthetic-user-007",
            steps=(
                ScenarioStep(
                    kind="message_scan",
                    title="Analyze password-reset SMS",
                    content_type=ContentType.ACCOUNT_VERIFICATION,
                    text="[SYNTHETIC DEMO] Microsoft Security Team: unusual sign-in detected. Your account will be "
                    "locked today. Verify your account at http://microsoft.com.account-security.example/login "
                    "and reply with the verification code we just sent you.",
                ),
                ScenarioStep(
                    kind="sim_event",
                    title="Simulate failed-login burst",
                    event_type=EventType.FAILED_LOGIN_BURST,
                    severity=RiskLevel.MEDIUM,
                    actor="synthetic-user-007",
                    description="[SIMULATED] 14 failed sign-in attempts in 3 minutes for synthetic-user-007 "
                    "from 203.0.113.77.",
                ),
                ScenarioStep(
                    kind="sim_event",
                    title="Simulate suspicious successful login",
                    event_type=EventType.SUSPICIOUS_LOGIN,
                    severity=RiskLevel.HIGH,
                    actor="synthetic-user-007",
                    description="[SIMULATED] Successful sign-in for synthetic-user-007 from a new device "
                    "and location immediately after the failed-login burst.",
                ),
                ScenarioStep(
                    kind="sim_event",
                    title="Raise account-takeover warning",
                    event_type=EventType.ACCOUNT_TAKEOVER_WARNING,
                    severity=RiskLevel.CRITICAL,
                    actor="synthetic-user-007",
                    description="[SIMULATED] Possible account takeover: recovery e-mail change requested "
                    "minutes after a suspicious login.",
                ),
                ScenarioStep(kind="create_incident", title="Open incident and link evidence"),
            ),
        ),
    )
}
