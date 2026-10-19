"""Offline URL feature analysis.

SECURITY: this module never performs network I/O. It does not resolve DNS, follow redirects or fetch
content. Every finding describes an observable property of the URL string itself.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

import idna
import tldextract

from app.services.detection.brands import (
    ABUSED_TLDS,
    COMMON_WORDS,
    EXECUTABLE_EXTENSIONS,
    HOMOGLYPHS,
    MULTI_CHAR_HOMOGLYPHS,
    OFFICIAL_DOMAINS,
    SENSITIVE_URL_KEYWORDS,
    SHORT_BRAND_TOKENS,
    TRUSTED_BRANDS,
    URL_SHORTENERS,
)
from app.services.detection.text import CONFUSABLES as _CONFUSABLES
from app.services.detection.text import find_mixed_script_tokens
from app.services.detection.types import Finding

URL_RULE_VERSION = "url-rules-1.0"

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled snapshot, no network
_RESERVED_TLDS = {"example", "test", "invalid", "localhost", "local", "internal", "lan"}
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_FORBIDDEN_SCHEME_RE = re.compile(r"^\s*(javascript|data|vbscript|file|blob)\s*:", re.IGNORECASE)
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_OBFUSCATED_IP_PART = re.compile(r"^(0x[0-9a-f]+|0[0-7]*|[1-9][0-9]*)$", re.IGNORECASE)
_REDIRECT_PARAMS = {
    "url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "next",
    "goto",
    "target",
    "dest",
    "destination",
    "continue",
    "return",
    "returnurl",
    "rurl",
    "u",
}

class UrlValidationError(ValueError):
    """The input cannot be analyzed as an http(s) URL."""


@dataclass
class UrlAnalysis:
    input_length: int
    normalized_url: str
    display_target: str
    scheme: str
    scheme_assumed: bool
    host: str
    host_unicode: str
    registered_domain: str | None
    subdomain: str
    suffix: str
    port: int | None
    is_ip: bool
    is_official_brand_domain: bool
    findings: list[Finding] = field(default_factory=list)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _parse_obfuscated_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Decodes inet_aton-style hosts that browsers accept: 3232235777, 0xC0A80001, 0300.0250.0.1 …"""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(_OBFUSCATED_IP_PART.match(p) for p in parts):
        return None
    try:
        nums = [
            int(p, 16) if p.lower().startswith("0x") else int(p, 8) if p.startswith("0") and p != "0" else int(p)
            for p in parts
        ]
    except ValueError:
        return None
    # Last part fills the remaining bytes.
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = 0
    for n in nums[:-1]:
        value = value * 256 + n
    value = value * (256 ** (5 - len(nums))) + nums[-1]
    try:
        return ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return None


def _homoglyph_skeleton(label: str) -> str:
    skeleton = label.lower().translate(_CONFUSABLES).translate(HOMOGLYPHS).replace("-", "")
    for src, dst in MULTI_CHAR_HOMOGLYPHS:
        skeleton = skeleton.replace(src, dst)
    return skeleton


def _tokens(value: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", value.lower()) if t]


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
            source="url_analyzer",
            weight=weight,
            explanation=explanation,
            evidence=evidence[:160] if evidence else None,
        )
    )


def analyze_url(raw: str, max_length: int = 2048) -> UrlAnalysis:
    if not raw or not raw.strip():
        raise UrlValidationError("URL is empty")
    if len(raw) > max_length:
        raise UrlValidationError(f"URL exceeds {max_length} characters")
    if _CONTROL_RE.search(raw):
        raise UrlValidationError("URL contains control characters")
    if _FORBIDDEN_SCHEME_RE.match(raw):
        raise UrlValidationError("Only http and https URLs can be analyzed")

    value = raw.strip()
    findings: list[Finding] = []
    # Defanged notation used in threat reports: hxxp://, example[.]com
    value = re.sub(r"^hxxp", "http", value, flags=re.IGNORECASE).replace("[.]", ".").replace("(.)", ".")
    scheme_assumed = False
    if not _SCHEME_RE.match(value):
        value = "http://" + value.lstrip("/")
        scheme_assumed = True

    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise UrlValidationError("Only http and https URLs can be analyzed")
    if " " in parts.netloc:
        raise UrlValidationError("Host contains whitespace")

    netloc = parts.netloc
    userinfo, _, hostport = netloc.rpartition("@")
    try:
        port = parts.port
    except ValueError as exc:
        raise UrlValidationError("Port is not a valid number") from exc
    raw_host = parts.hostname or ""
    if not raw_host:
        raise UrlValidationError("URL has no host")

    # --- Encoding anomalies -------------------------------------------------
    if "%" in hostport:
        raw_host = unquote(raw_host).lower()
        _add(
            findings,
            "URL_ENCODED_HOST",
            "Percent-encoded hostname",
            "deception",
            "medium",
            15,
            "The hostname contains percent-encoding. Legitimate sites essentially never encode their own "
            "hostname; this can hide the real destination from a quick visual check.",
            hostport,
        )
    path_and_query = parts.path + ("?" + parts.query if parts.query else "")
    lowered_pq = path_and_query.lower()
    if (
        "%25" in lowered_pq
        or re.search(r"%2f|%40|%5c|%3a%2f%2f", lowered_pq)
        or (len(path_and_query) > 30 and path_and_query.count("%") * 3 > len(path_and_query) * 0.4)
    ):
        _add(
            findings,
            "URL_ENCODING_ANOMALY",
            "Unusual URL encoding",
            "deception",
            "medium",
            12,
            "The path or query uses double-encoding, encoded slashes/@ signs, or is mostly percent-encoded. "
            "These patterns are used to evade filters or disguise embedded destinations.",
            path_and_query[:120],
        )

    # --- Credentials / user-info ---------------------------------------------
    if userinfo:
        _add(
            findings,
            "URL_USERINFO",
            "Text before '@' in the address",
            "deception",
            "high",
            30,
            "Everything before the '@' sign is treated as a username and ignored when choosing the "
            "destination. Attackers use this to make a URL appear to start with a trusted name while it "
            "actually points elsewhere.",
            f"{userinfo[:40]}@{hostport[:60]}",
        )

    # --- Host classification -------------------------------------------------
    host = raw_host.rstrip(".").lower()
    is_ip = False
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        ip_obj = ipaddress.ip_address(host)
        is_ip = True
        _add(
            findings,
            "URL_IP_HOST",
            "Raw IP address instead of a domain",
            "host",
            "medium",
            22,
            "The link points at a numeric IP address. Most legitimate consumer services use domain names; "
            "raw IPs avoid domain-based reputation and make the operator harder to identify.",
            host,
        )
    except ValueError:
        obfuscated = _parse_obfuscated_ipv4(host)
        if obfuscated is not None and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            ip_obj = obfuscated
            is_ip = True
            _add(
                findings,
                "URL_OBFUSCATED_IP",
                "Obfuscated IP address",
                "deception",
                "high",
                30,
                f"The host '{host}' is a disguised numeric IP address (decodes to {obfuscated}). This "
                "encoding has no legitimate use in everyday links.",
                host,
            )
    if ip_obj is not None and (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_unspecified
    ):
        doc_net = ipaddress.ip_network("203.0.113.0/24")
        if not (isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in doc_net):
            _add(
                findings,
                "URL_INTERNAL_HOST",
                "Internal or reserved network address",
                "host",
                "medium",
                15,
                "The address points to a private, loopback, link-local or reserved range (for example a "
                "home router or cloud metadata service). Links in messages should not target these.",
                str(ip_obj),
            )

    # --- IDN / punycode -------------------------------------------------------
    host_unicode = host
    host_ascii = host
    if not is_ip:
        if any(ord(c) > 127 for c in host):
            try:
                host_ascii = idna.encode(host, uts46=True).decode("ascii")
            except idna.IDNAError:
                host_ascii = host.encode("ascii", "replace").decode()
        labels = host_ascii.split(".")
        if any(label.startswith("xn--") for label in labels):
            try:
                host_unicode = idna.decode(host_ascii)
            except idna.IDNAError:
                host_unicode = host_ascii
            _add(
                findings,
                "URL_PUNYCODE",
                "Internationalized (punycode) domain",
                "deception",
                "medium",
                15,
                f"The domain uses internationalized characters ('{host_ascii}' displays as "
                f"'{host_unicode}'). This is legitimate for many languages but is also used to imitate "
                "familiar domains with lookalike letters.",
                host_ascii,
            )
            mixed = find_mixed_script_tokens(host_unicode.replace(".", " "))
            if mixed:
                _add(
                    findings,
                    "URL_MIXED_SCRIPT",
                    "Mixed alphabets in one domain label",
                    "deception",
                    "high",
                    30,
                    "A single domain label mixes Latin letters with Cyrillic/Greek letters that look "
                    "identical. This is a classic homograph spoofing technique.",
                    ", ".join(mixed),
                )
        host = host_ascii

    # --- Domain structure -----------------------------------------------------
    subdomain = ""
    suffix = ""
    registered: str | None = None
    domain_label = ""
    if not is_ip:
        ext = _EXTRACT(host)
        subdomain, domain_label, suffix = ext.subdomain, ext.domain, ext.suffix
        if not suffix:
            labels = host.split(".")
            if len(labels) >= 2 and labels[-1] in _RESERVED_TLDS:
                suffix = labels[-1]
                domain_label = labels[-2]
                subdomain = ".".join(labels[:-2])
                _add(
                    findings,
                    "URL_RESERVED_TLD",
                    "Reserved or internal top-level domain",
                    "host",
                    "info",
                    0,
                    f"'.{suffix}' is reserved (e.g. RFC 2606) or internal and does not resolve on the public "
                    "internet. Often seen in examples, tests and internal networks.",
                    suffix,
                )
            else:
                _add(
                    findings,
                    "URL_NO_PUBLIC_SUFFIX",
                    "No recognized public domain suffix",
                    "host",
                    "low",
                    6,
                    "The host does not end in a recognized public suffix in SentinelAI's offline list. It "
                    "may be an internal name, a typo, or a deliberately unusual host.",
                    host,
                )
        if domain_label and suffix:
            registered = f"{domain_label}.{suffix}"

        sub_labels = [s for s in subdomain.split(".") if s]
        if len(sub_labels) >= 3:
            _add(
                findings,
                "URL_SUBDOMAIN_DEPTH",
                "Many nested subdomains",
                "host",
                "low",
                10,
                f"The host has {len(sub_labels)} subdomain levels. Long chains are sometimes used to push the "
                "real domain out of view on small screens. Deep subdomains alone are common on large "
                "platforms.",
                subdomain[:120],
            )
        if suffix and suffix.split(".")[-1] in ABUSED_TLDS:
            _add(
                findings,
                "URL_ABUSED_TLD",
                f"Top-level domain '.{suffix}' is frequently abused",
                "host",
                "low",
                8,
                "This top-level domain is cheap or loosely managed and appears often in abuse reports. "
                "Many legitimate sites use it too, so this is a weak signal on its own.",
                suffix,
            )

    is_official = registered in OFFICIAL_DOMAINS if registered else False
    if is_official:
        _add(
            findings,
            "URL_OFFICIAL_DOMAIN",
            "Matches a built-in official brand domain",
            "brand",
            "info",
            0,
            f"'{registered}' appears in SentinelAI's small built-in list of official brand domains. This is "
            "not a live reputation check, and a legitimate domain can still host or redirect to harmful "
            "content.",
            registered,
        )

    # --- Brand impersonation heuristics ---------------------------------------
    brand_hit = False
    if not is_ip and not is_official and domain_label:
        label_tokens = _tokens(domain_label)
        unicode_label = domain_label
        if domain_label.startswith("xn--"):
            try:
                unicode_label = idna.decode(domain_label)
            except idna.IDNAError:
                unicode_label = domain_label
        skeleton = _homoglyph_skeleton(unicode_label)
        compact = domain_label.replace("-", "")
        # Candidates: the whole label (hyphens removed) and each hyphen/digit-separated token.
        candidates = {compact, *(t for t in re.split(r"-+", domain_label.lower()) if t)}
        lookalike_brand: str | None = None
        for brand in TRUSTED_BRANDS:
            if brand in label_tokens:
                continue  # exact brand token: handled as brand-in-domain below
            for cand in candidates:
                if cand in COMMON_WORDS or len(cand) < 4:
                    continue
                cand_skeleton = skeleton if cand == compact else _homoglyph_skeleton(cand)
                if cand_skeleton == brand and cand != brand:
                    lookalike_brand = brand
                elif brand not in SHORT_BRAND_TOKENS:
                    distance = levenshtein(cand, brand)
                    if 0 < distance <= (1 if len(brand) <= 7 else 2):
                        lookalike_brand = brand
                if lookalike_brand:
                    break
            if lookalike_brand:
                break
        if lookalike_brand:
            brand_hit = True
            official = TRUSTED_BRANDS[lookalike_brand]
            _add(
                findings,
                "URL_LOOKALIKE",
                f"Lookalike of '{lookalike_brand}'",
                "brand",
                "high",
                35,
                f"'{domain_label}' closely resembles '{lookalike_brand}' (character substitution or a small "
                f"typo) but is not an official {lookalike_brand} domain ({', '.join(official[:3])}). "
                "Lookalike domains are a primary phishing technique.",
                registered,
            )
        else:
            for brand, official in TRUSTED_BRANDS.items():
                if brand in label_tokens or (len(brand) >= 6 and compact.startswith(brand) and compact != brand):
                    brand_hit = True
                    _add(
                        findings,
                        "URL_BRAND_IN_DOMAIN",
                        f"Uses the brand name '{brand}' in an unrelated domain",
                        "brand",
                        "medium",
                        18,
                        f"The domain '{registered}' contains '{brand}' but is not one of its known official "
                        f"domains ({', '.join(official[:3])}). Scam sites often combine a brand with words "
                        "like 'secure', 'verify' or 'support'.",
                        registered,
                    )
                    break
        if subdomain:
            sub_tokens = set(_tokens(subdomain))
            for brand, official in TRUSTED_BRANDS.items():
                if brand in sub_tokens or any(f".{d}." in f".{subdomain}." for d in official):
                    brand_hit = True
                    _add(
                        findings,
                        "URL_BRAND_IN_SUBDOMAIN",
                        f"'{brand}' appears only in the subdomain",
                        "brand",
                        "high",
                        28,
                        f"'{brand}' appears in the subdomain while the real registered domain is "
                        f"'{registered or host}'. Readers often mistake the left-most part of a host for the "
                        "site they are visiting.",
                        host[:120],
                    )
                    break

    # --- Port ---------------------------------------------------------------
    if port is not None and port not in (80, 443):
        _add(
            findings,
            "URL_NONSTANDARD_PORT",
            f"Non-standard port {port}",
            "host",
            "medium",
            12,
            "Public websites almost always use the default ports 80/443. A custom port can indicate "
            "a temporary, self-hosted or compromised server.",
            f":{port}",
        )

    # --- Transport ----------------------------------------------------------
    if scheme == "http" and not scheme_assumed:
        _add(
            findings,
            "URL_NO_TLS",
            "Unencrypted HTTP",
            "transport",
            "low",
            8,
            "The link uses http:// so anything entered on the page would travel unencrypted. This is a "
            "risk signal, not proof of malicious intent.",
            "http://",
        )

    # --- Redirection ----------------------------------------------------------
    is_shortener = registered in URL_SHORTENERS or host in URL_SHORTENERS
    if is_shortener:
        _add(
            findings,
            "URL_SHORTENER",
            "Link shortener hides the destination",
            "redirection",
            "low",
            10,
            "Shortened links conceal where they lead. SentinelAI does not expand or visit them, so the final "
            "destination is unknown. Shorteners are also widely used legitimately.",
            host,
        )
    query_params = parse_qsl(parts.query, keep_blank_values=True)
    if any(
        k.lower() in _REDIRECT_PARAMS and re.match(r"^(https?:)?//", unquote(v), re.I) for k, v in query_params
    ) or re.search(r"https?(:|%3a)(//|%2f%2f)", lowered_pq):
        _add(
            findings,
            "URL_EMBEDDED_URL",
            "Embedded redirect to another URL",
            "redirection",
            "medium",
            10,
            "The link carries another URL inside its path or query string. Open-redirect chains are used to "
            "launder malicious destinations through trusted-looking domains.",
            path_and_query[:120],
        )

    # --- Content hints ----------------------------------------------------------
    keyword_space = f"{subdomain}.{domain_label} {parts.path} {parts.query}".lower()
    keywords = sorted({k for k in SENSITIVE_URL_KEYWORDS if k in keyword_space})
    if keywords:
        _add(
            findings,
            "URL_SENSITIVE_KEYWORDS",
            "Account or payment wording in the URL",
            "content",
            "low",
            8,
            "The URL contains words associated with sign-in or payment pages ("
            + ", ".join(keywords[:5])
            + "). Normal on genuine sites; concerning combined with other signals.",
            ", ".join(keywords[:5]),
        )
    lowered_path = parts.path.lower()
    if lowered_path.endswith(EXECUTABLE_EXTENSIONS):
        _add(
            findings,
            "URL_EXECUTABLE",
            "Direct link to an executable or installer",
            "content",
            "high",
            18,
            "The link points straight at an installable file (e.g. .apk/.exe). Installing software from "
            "message links is a common malware delivery route.",
            parts.path[-60:],
        )
    if len(value) > 200:
        _add(
            findings,
            "URL_LONG",
            "Unusually long URL",
            "content",
            "low",
            5,
            f"The URL is {len(value)} characters long. Very long URLs can hide the important parts.",
            None,
        )

    # --- Combinations -----------------------------------------------------------
    ids = {f.rule_id for f in findings}
    if keywords and "URL_NO_TLS" in ids:
        _add(
            findings,
            "URL_COMBO_INSECURE_LOGIN",
            "Sign-in/payment wording over unencrypted HTTP",
            "combination",
            "medium",
            10,
            "Account or payment wording together with an unencrypted connection: a genuine sign-in page "
            "would use HTTPS.",
        )
    if keywords and brand_hit:
        _add(
            findings,
            "URL_COMBO_BRAND_CREDENTIAL",
            "Brand imitation combined with account wording",
            "combination",
            "high",
            12,
            "The URL both imitates a brand and uses sign-in/verification wording, the typical shape of a "
            "credential-phishing link.",
        )
    if keywords and is_ip:
        _add(
            findings,
            "URL_COMBO_IP_CREDENTIAL",
            "Account wording on a raw IP address",
            "combination",
            "medium",
            10,
            "Sign-in or payment wording on a bare IP address is rarely legitimate.",
        )

    port_part = f":{port}" if port is not None else ""
    display_host = f"[{host}]" if isinstance(ip_obj, ipaddress.IPv6Address) else host
    normalized = f"{scheme}://{display_host}{port_part}{parts.path or '/'}"
    if parts.query:
        normalized += f"?{parts.query}"

    return UrlAnalysis(
        input_length=len(raw),
        normalized_url=normalized,
        display_target=f"{scheme}://{display_host}{port_part}",
        scheme=scheme,
        scheme_assumed=scheme_assumed,
        host=host,
        host_unicode=host_unicode,
        registered_domain=registered,
        subdomain=subdomain,
        suffix=suffix,
        port=port,
        is_ip=is_ip,
        is_official_brand_domain=is_official,
        findings=findings,
    )
