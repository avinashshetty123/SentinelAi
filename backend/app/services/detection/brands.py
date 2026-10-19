"""Reference data for offline URL heuristics.

This is a small, hand-curated list used for lookalike comparisons. It is not a reputation database.
"""

from __future__ import annotations

# brand token -> official registrable domains
TRUSTED_BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me"),
    "google": (
        "google.com",
        "google.co.in",
        "youtube.com",
        "gmail.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "googlemail.com",
        "googlesource.com",
    ),
    "microsoft": ("microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "whatsapp.net"),
    "linkedin": ("linkedin.com",),
    "github": ("github.com",),
    "dropbox": ("dropbox.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "fedex": ("fedex.com",),
    "dhl": ("dhl.com",),
    "usps": ("usps.com",),
    "ups": ("ups.com",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com",),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "sbi": ("onlinesbi.sbi", "sbi.co.in"),
    "hdfc": ("hdfcbank.com",),
    "icici": ("icicibank.com",),
    "paytm": ("paytm.com",),
    "phonepe": ("phonepe.com",),
    "irs": ("irs.gov",),
    "indiapost": ("indiapost.gov.in",),
}

# Ordinary words within edit distance of a brand; never flagged as lookalikes.
COMMON_WORDS = {"finance", "phone", "chance", "apply", "paypad", "stream", "steamy", "googly", "amazing"}

# Tokens too short/generic to use for lookalike edit-distance comparisons (high false-positive risk).
SHORT_BRAND_TOKENS = {"ups", "dhl", "sbi", "irs", "hdfc", "usps", "chase", "apple", "steam"}

OFFICIAL_DOMAINS: set[str] = {d for domains in TRUSTED_BRANDS.values() for d in domains}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "tiny.cc",
    "t.ly",
    "s.id",
    "v.gd",
    "lnkd.in",
    "bl.ink",
    "short.io",
    "trib.al",
    "qr.ae",
    "surl.li",
    "u.to",
}

# TLDs frequently seen in abuse reports because they are cheap or loosely managed. Many legitimate
# sites use them too, so this is only a weak signal.
ABUSED_TLDS = {
    "zip",
    "mov",
    "xyz",
    "top",
    "tk",
    "gq",
    "ml",
    "cf",
    "ga",
    "click",
    "country",
    "work",
    "rest",
    "cam",
    "icu",
    "sbs",
    "cfd",
    "buzz",
    "monster",
    "quest",
    "lol",
    "bond",
    "support",
    "live",
    "shop",
}

SENSITIVE_URL_KEYWORDS = (
    "login",
    "log-in",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "banking",
    "wallet",
    "kyc",
    "confirm",
    "password",
    "unlock",
    "suspend",
    "billing",
    "invoice",
    "refund",
    "reward",
    "claim",
    "auth",
    "webscr",
    "recover",
)

EXECUTABLE_EXTENSIONS = (
    ".apk",
    ".exe",
    ".scr",
    ".msi",
    ".bat",
    ".cmd",
    ".vbs",
    ".jar",
    ".ps1",
    ".dmg",
    ".pkg",
    ".iso",
    ".hta",
    ".lnk",
)

# Visual substitutions used in lookalike domains.
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
MULTI_CHAR_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"))
