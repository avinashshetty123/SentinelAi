from __future__ import annotations

import socket

import pytest

from app.services.detection.url_analyzer import UrlValidationError, analyze_url, levenshtein
from app.services.scoring.engine import score_findings


def ids(url: str) -> set[str]:
    return {f.rule_id for f in analyze_url(url).findings}


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://example.com/", "URL_NO_TLS"),
        ("https://paypal.com@evil.example/", "URL_USERINFO"),
        ("http://203.0.113.5/login", "URL_IP_HOST"),
        ("http://3232235777/", "URL_OBFUSCATED_IP"),
        ("http://0x7f.0.0.1/", "URL_OBFUSCATED_IP"),
        ("http://192.168.1.1/admin", "URL_INTERNAL_HOST"),
        ("http://169.254.169.254/latest/meta-data", "URL_INTERNAL_HOST"),
        ("https://a.b.c.d.example.com/", "URL_SUBDOMAIN_DEPTH"),
        ("https://xn--pypal-4ve.com/", "URL_PUNYCODE"),
        ("https://xn--pypal-4ve.com/", "URL_MIXED_SCRIPT"),
        ("https://example.com/%252e%252e/", "URL_ENCODING_ANOMALY"),
        ("https://example.com:8443/", "URL_NONSTANDARD_PORT"),
        ("https://bit.ly/3xYz", "URL_SHORTENER"),
        ("https://paypa1.com/", "URL_LOOKALIKE"),
        ("https://rnicrosoft.com/", "URL_LOOKALIKE"),
        ("https://paypal.com.secure-login.example/", "URL_BRAND_IN_SUBDOMAIN"),
        ("https://sbi-kyc-update.xyz/", "URL_BRAND_IN_DOMAIN"),
        ("https://example.com/files/update.apk", "URL_EXECUTABLE"),
        ("https://example.com/r?url=https://evil.example", "URL_EMBEDDED_URL"),
        ("https://free-gift.xyz/", "URL_ABUSED_TLD"),
    ],
)
def test_url_checks(url: str, expected: str) -> None:
    assert expected in ids(url)


@pytest.mark.parametrize(
    "url",
    ["https://www.google.com/search?q=weather", "https://github.com/org/repo", "https://login.microsoftonline.com/",
     "https://finance.com/", "https://en.wikipedia.org/wiki/Phishing"],
)
def test_legitimate_urls_score_low(url: str) -> None:
    result = score_findings(analyze_url(url).findings)
    assert result.level.value == "LOW"
    assert "URL_LOOKALIKE" not in ids(url)


def test_http_alone_is_not_high_risk() -> None:
    assert score_findings(analyze_url("http://example.org/").findings).level.value == "LOW"


def test_shortener_alone_is_not_high_risk() -> None:
    assert score_findings(analyze_url("https://bit.ly/abc").findings).level.value == "LOW"


def test_combined_signals_raise_risk() -> None:
    result = score_findings(analyze_url("http://user@203.0.113.9:8080/secure/login/update.apk").findings)
    assert result.level.value in ("HIGH", "CRITICAL")


@pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd", "ftp://x.example/",
                                 "", "   ", "http://", "http://exa mple.com/", "http://example.com:99999/"])
def test_invalid_urls_rejected(url: str) -> None:
    with pytest.raises(UrlValidationError):
        analyze_url(url)


def test_too_long_url_rejected() -> None:
    with pytest.raises(UrlValidationError):
        analyze_url("https://example.com/" + "a" * 3000, max_length=2048)


def test_scheme_assumed_and_defanged() -> None:
    a = analyze_url("hxxp://evil[.]example/login")
    assert a.host == "evil.example" and a.scheme == "http"
    b = analyze_url("example.com/path")
    assert b.scheme_assumed and "URL_NO_TLS" not in {f.rule_id for f in b.findings}


def test_display_target_excludes_path_and_query() -> None:
    a = analyze_url("https://example.com/reset?token=SECRET123")
    assert a.display_target == "https://example.com"
    assert "SECRET123" not in a.display_target


def test_analysis_never_touches_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    for url in ("https://paypa1.com/login", "http://bit.ly/x", "https://xn--pypal-4ve.com", "http://3232235777/"):
        analyze_url(url)


def test_levenshtein() -> None:
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("google", "google") == 0
    assert levenshtein("abc", "") == 3
