"""Text normalization, URL extraction and evidence excerpts."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Zero-width and bidi-control characters frequently used to break keyword filters or disguise text.
_INVISIBLE = {
    "​",
    "‌",
    "‍",
    "⁠",
    "﻿",
    "­",
    "‪",
    "‫",
    "‬",
    "‭",
    "‮",
    "⁦",
    "⁧",
    "⁨",
    "⁩",
}
_WS_RE = re.compile(r"[ \t\r\f\v]+")
_MANY_NEWLINES = re.compile(r"\n{3,}")

_URL_RE = re.compile(
    r"""(?ix)
    \b(?:
        (?:https?|hxxps?)://[^\s<>"'`]+            # explicit scheme (incl. defanged hxxp)
      | www\.[^\s<>"'`]+                            # www. prefix
      | (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
        (?:com|net|org|io|ly|co|info|xyz|top|in|me|link|click|online|site|app|biz|ru|cn|tk|gq|ml|cf|ga|
           live|shop|store|club|icu|vip|cc|ws|to|gl|gd|su|zip|mov|support|help|page|website|space|fun)
        (?:/[^\s<>"'`]*)?                           # bare domain with a common/abused TLD
    )
    """
)
_TRAILING_PUNCT = ".,;:!?)]}>'\"`"


# Latin lookalikes from Cyrillic/Greek/Armenian used in IDN homograph attacks.
CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ԁ": "d",
        "ѕ": "s",
        "ӏ": "l",
        "һ": "h",
        "ԛ": "q",
        "ԝ": "w",
        "ո": "n",
        "ս": "u",
        "ɡ": "g",
        "ν": "v",
        "ο": "o",
        "α": "a",
        "ρ": "p",
        "τ": "t",
        "κ": "k",
        "ι": "i",
        "ϲ": "c",
        "ѵ": "v",
        "ɑ": "a",
    }
)


@dataclass(frozen=True)
class NormalizedText:
    original_length: int
    text: str  # NFKC-normalized, invisible characters removed, whitespace collapsed
    invisible_char_count: int
    mixed_script_tokens: tuple[str, ...]


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN"):
        if name.startswith(script):
            return script
    return "OTHER"


def find_mixed_script_tokens(text: str, limit: int = 5) -> tuple[str, ...]:
    """Words mixing Latin with Cyrillic/Greek letters (e.g. 'pаypal' with a Cyrillic 'а')."""
    found: list[str] = []
    for token in re.findall(r"\w{3,}", text):
        scripts = {s for s in (_script_of(c) for c in token) if s and s != "OTHER"}
        if "LATIN" in scripts and len(scripts) > 1:
            found.append(token[:40])
            if len(found) >= limit:
                break
    return tuple(found)


def normalize_text(raw: str) -> NormalizedText:
    invisible = sum(1 for ch in raw if ch in _INVISIBLE)
    cleaned = "".join(ch for ch in raw if ch not in _INVISIBLE)
    # Mixed-script detection must run before NFKC (NFKC does not fold Cyrillic into Latin, but be explicit).
    mixed = find_mixed_script_tokens(cleaned)
    if mixed:
        # Fold lookalike letters to Latin inside mixed-script words so keyword rules still match them.
        cleaned = re.sub(r"\w{3,}", lambda m: m.group(0).translate(CONFUSABLES) if m.group(0) in mixed
                         else m.group(0), cleaned)
    text = unicodedata.normalize("NFKC", cleaned)
    text = "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch)[0] != "C")
    text = _WS_RE.sub(" ", text)
    text = _MANY_NEWLINES.sub("\n\n", text).strip()
    return NormalizedText(
        original_length=len(raw),
        text=text,
        invisible_char_count=invisible,
        mixed_script_tokens=mixed,
    )


def extract_urls(text: str, limit: int = 10) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(text):
        candidate = match.group(0).rstrip(_TRAILING_PUNCT)
        # Skip things like "e.g." or file names "report.zip" without a path being mistaken for URLs is
        # acceptable: URL findings are weighted evidence, not verdicts.
        if len(candidate) < 4:
            continue
        key = candidate.lower()
        if key in seen:
            continue
        seen.add(key)
        urls.append(candidate)
        if len(urls) >= limit:
            break
    return urls


def excerpt(text: str, start: int, end: int, radius: int = 40, max_len: int = 160) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    snippet = text[lo:hi].replace("\n", " ").strip()
    if len(snippet) > max_len:
        snippet = snippet[: max_len - 1] + "…"
    prefix = "…" if lo > 0 else ""
    suffix = "…" if hi < len(text) and not snippet.endswith("…") else ""
    return f"{prefix}{snippet}{suffix}"


_LONG_DIGITS = re.compile(r"(?<!\w)(?:\d[ -]?){6,}\d?(?!\w)")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def minimize_for_llm(text: str, max_chars: int) -> str:
    """Data minimization before sending text to an external LLM provider: long digit runs (OTPs, card,
    account and phone numbers) and e-mail addresses are masked, and the text is truncated."""
    masked = _EMAIL.sub("[EMAIL]", text)
    masked = _LONG_DIGITS.sub("[NUMBER] ", masked)
    if len(masked) > max_chars:
        masked = masked[:max_chars] + " [TRUNCATED]"
    return masked
