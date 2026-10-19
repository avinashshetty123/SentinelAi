"""Offline e-mail header forensics.

Parses pasted raw headers and checks the signals that matter for spoofing/phishing:
SPF / DKIM / DMARC results recorded by the receiving server, From vs Reply-To / Return-Path domain
mismatches, brand names in the display name, lookalike sender domains, and the relay path.

Nothing is fetched (no DNS lookups) — we read what the receiving mail server already recorded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.parser import HeaderParser
from email.utils import getaddresses, parseaddr

from app.services.detection.brands import OFFICIAL_DOMAINS, TRUSTED_BRANDS
from app.services.detection.types import Finding
from app.services.detection.url_analyzer import UrlValidationError, analyze_url

EMAIL_RULE_VERSION = "email-rules-1.0"

_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")


@dataclass
class EmailHeaderAnalysis:
    from_address: str | None
    from_display: str | None
    from_domain: str | None
    reply_to_domain: str | None
    return_path_domain: str | None
    subject: str | None
    auth: dict[str, str]
    hops: list[dict[str, str | None]]
    findings: list[Finding] = field(default_factory=list)


def _domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip(" >").lower() or None


def _org(domain: str | None) -> str | None:
    """Registrable domain via the same offline public-suffix logic used for URLs."""
    if not domain:
        return None
    try:
        return analyze_url(f"http://{domain}/").registered_domain or domain
    except UrlValidationError:
        return domain


def _add(
    findings: list[Finding],
    rule_id: str,
    title: str,
    category: str,
    severity: str,
    weight: int,
    explanation: str,
    evidence: str | None = None,
) -> None:
    findings.append(
        Finding(
            rule_id=rule_id,
            title=title,
            category=category,
            severity=severity,  # type: ignore[arg-type]
            source="rule",
            weight=weight,
            explanation=explanation,
            evidence=evidence[:160] if evidence else None,
        )
    )


def analyze_email_headers(raw: str) -> EmailHeaderAnalysis:
    # Accept headers with or without a body; unfold continuation lines via the stdlib parser.
    headers = HeaderParser().parsestr(raw.strip() + "\n\n", headersonly=True)
    findings: list[Finding] = []

    from_display, parsed_from = parseaddr(headers.get("From", "") or "")
    from_addr: str | None = parsed_from or None
    from_domain = _domain(from_addr)
    reply_to = [a for _, a in getaddresses(headers.get_all("Reply-To", []) or []) if a]
    reply_domain = _domain(reply_to[0]) if reply_to else None
    return_path = parseaddr(headers.get("Return-Path", "") or "")[1]
    return_domain = _domain(return_path)

    # --- Authentication results (as recorded by the receiving server) ---------------------------------
    auth: dict[str, str] = {}
    for value in (headers.get_all("Authentication-Results", []) or []) + (
        headers.get_all("ARC-Authentication-Results", []) or []
    ):
        for mech, result in _AUTH_RE.findall(str(value)):
            auth.setdefault(mech.lower(), result.lower())
    received_spf = headers.get("Received-SPF")
    if "spf" not in auth and received_spf:
        auth["spf"] = str(received_spf).split()[0].lower()

    if not auth:
        _add(
            findings,
            "EMAIL_NO_AUTH_RESULTS",
            "No authentication results recorded",
            "authentication",
            "low",
            8,
            "The headers contain no Authentication-Results/Received-SPF lines, so SPF, DKIM and DMARC cannot be "
            "assessed. Paste the full headers from 'Show original' / 'View source' for a complete check.",
        )
    spf, dkim, dmarc = auth.get("spf"), auth.get("dkim"), auth.get("dmarc")
    if dmarc == "fail":
        _add(
            findings,
            "EMAIL_DMARC_FAIL",
            "DMARC failed",
            "authentication",
            "high",
            30,
            "The receiving server recorded a DMARC failure: the visible From domain is not authenticated by SPF or "
            "DKIM in alignment. This is the strongest technical sign of a spoofed sender.",
            f"dmarc={dmarc}",
        )
    if spf in ("fail", "softfail"):
        _add(
            findings,
            "EMAIL_SPF_FAIL",
            f"SPF {spf}",
            "authentication",
            "high" if spf == "fail" else "medium",
            20 if spf == "fail" else 10,
            "The sending server is not authorised by the envelope domain's SPF record.",
            f"spf={spf}",
        )
    if dkim in ("fail", "invalid", "permerror"):
        _add(
            findings,
            "EMAIL_DKIM_FAIL",
            "DKIM signature failed",
            "authentication",
            "medium",
            16,
            "The message's DKIM signature did not verify, so its content or claimed origin may have been altered.",
            f"dkim={dkim}",
        )
    if spf in ("none", "neutral") and dkim in (None, "none") and dmarc in (None, "none"):
        _add(
            findings,
            "EMAIL_WEAK_AUTH",
            "Sender has no effective authentication",
            "authentication",
            "low",
            8,
            "No passing SPF, DKIM or DMARC result. Legitimate large senders almost always authenticate.",
            f"spf={spf} dkim={dkim} dmarc={dmarc}",
        )

    # --- Sender identity mismatches ---------------------------------------------------------------------
    from_org = _org(from_domain)
    if reply_domain and from_org and _org(reply_domain) != from_org:
        _add(
            findings,
            "EMAIL_REPLYTO_MISMATCH",
            "Replies go to a different domain",
            "sender_mismatch",
            "high",
            18,
            f"Replies would go to '{reply_domain}', not the sender's domain '{from_domain}'. Scammers use this to "
            "receive answers while displaying a trusted From address.",
            f"Reply-To: {reply_to[0]}",
        )
    if return_domain and from_org and _org(return_domain) != from_org:
        _add(
            findings,
            "EMAIL_RETURNPATH_MISMATCH",
            "Bounce address uses a different domain",
            "sender_mismatch",
            "low",
            6,
            "The Return-Path (envelope sender) differs from the From domain. Common for newsletters and "
            "mailing services, so this is a weak signal on its own.",
            f"Return-Path: {return_path}",
        )

    display = (from_display or "").strip()
    if display:
        embedded = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", display)
        if embedded and from_domain and _org(embedded.group(1).lower()) != from_org:
            _add(
                findings,
                "EMAIL_DISPLAY_ADDRESS_SPOOF",
                "Display name shows a different e-mail address",
                "sender_mismatch",
                "high",
                22,
                "The display name contains an address on another domain, so mail "
                "apps show a trusted-looking address while the real sender is different.",
                f"{display} <{from_addr}>",
            )
        lowered = re.sub(r"[^a-z0-9]", "", display.lower())
        for brand, official in TRUSTED_BRANDS.items():
            if len(brand) >= 4 and brand in lowered and from_org and from_org not in official:
                _add(
                    findings,
                    "EMAIL_DISPLAY_BRAND_SPOOF",
                    f"Display name claims '{brand}'",
                    "sender_mismatch",
                    "high",
                    20,
                    f"The sender calls itself '{display}' but the real address is on '{from_domain}', "
                    f"not an official {brand} domain.",
                    f"{display} <{from_addr}>",
                )
                break

    # --- Sender domain lookalikes (reuses the URL brand heuristics) ------------------------------------
    if from_domain and from_org not in OFFICIAL_DOMAINS:
        try:
            for f in analyze_url(f"https://{from_domain}/").findings:
                if f.rule_id in (
                    "URL_LOOKALIKE",
                    "URL_BRAND_IN_DOMAIN",
                    "URL_BRAND_IN_SUBDOMAIN",
                    "URL_MIXED_SCRIPT",
                    "URL_PUNYCODE",
                    "URL_ABUSED_TLD",
                ):
                    f.rule_id = f.rule_id.replace("URL_", "EMAIL_DOMAIN_")
                    f.category = "brand"
                    f.source = "rule"
                    f.title = f"Sender domain: {f.title}"
                    findings.append(f)
        except UrlValidationError:
            pass

    # --- Relay path ------------------------------------------------------------------------------------
    hops: list[dict[str, str | None]] = []
    for value in reversed(headers.get_all("Received", []) or []):  # oldest first
        text = " ".join(str(value).split())
        frm = re.search(r"\bfrom\s+(\S+)", text)
        by = re.search(r"\bby\s+(\S+)", text)
        ip = _IP_RE.search(text)
        hops.append(
            {
                "from": frm.group(1)[:80] if frm else None,
                "by": by.group(1)[:80] if by else None,
                "ip": ip.group(1) if ip else None,
            }
        )
    if len(hops) > 8:
        _add(
            findings,
            "EMAIL_MANY_HOPS",
            f"Unusually long relay path ({len(hops)} hops)",
            "relay",
            "low",
            5,
            "Messages normally pass through a handful of servers. Long chains can indicate relaying through "
            "compromised or anonymising infrastructure.",
        )

    return EmailHeaderAnalysis(
        from_address=from_addr,
        from_display=display or None,
        from_domain=from_domain,
        reply_to_domain=reply_domain,
        return_path_domain=return_domain,
        subject=(str(headers.get("Subject"))[:200] if headers.get("Subject") else None),
        auth=auth,
        hops=hops[:20],
        findings=findings,
    )
