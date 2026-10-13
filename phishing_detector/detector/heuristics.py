"""
heuristics.py — Lexical analysis, homoglyphs, brand spoofing, entropy, keywords.
"""
import re
import math
from urllib.parse import urlparse, unquote
from dataclasses import dataclass, field
from typing import List, Tuple

# ── Known brand targets ──────────────────────────────────────────────
BRAND_TARGETS = {
    "paypal":     ["paypal.com"],
    "google":     ["google.com", "gmail.com", "accounts.google.com"],
    "microsoft":  ["microsoft.com", "live.com", "outlook.com", "office.com", "login.microsoftonline.com"],
    "apple":      ["apple.com", "icloud.com"],
    "amazon":     ["amazon.com", "amazon.in", "amazon.co.uk"],
    "facebook":   ["facebook.com", "fb.com"],
    "instagram":  ["instagram.com"],
    "twitter":    ["twitter.com", "x.com"],
    "netflix":    ["netflix.com"],
    "linkedin":   ["linkedin.com"],
    "whatsapp":   ["whatsapp.com", "web.whatsapp.com"],
    "telegram":   ["telegram.org", "t.me"],
    "binance":    ["binance.com"],
    "coinbase":   ["coinbase.com"],
    "metamask":   ["metamask.io"],
    "sbi":        ["onlinesbi.sbi", "sbi.co.in"],
    "hdfc":       ["hdfcbank.com"],
    "icici":      ["icicibank.com"],
    "paytm":      ["paytm.com"],
    "phonepe":    ["phonepe.com"],
    "gpay":       ["pay.google.com"],
    "chase":      ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "dropbox":    ["dropbox.com"],
    "adobe":      ["adobe.com"],
    "yahoo":      ["yahoo.com"],
    "ebay":       ["ebay.com"],
    "dhl":        ["dhl.com"],
    "fedex":      ["fedex.com"],
    "usps":       ["usps.com"],
}

# ── Homoglyph / Cyrillic mappings ────────────────────────────────────
HOMOGLYPHS = {
    '\u0430': 'a',  # Cyrillic а
    '\u0435': 'e',  # Cyrillic е
    '\u043e': 'o',  # Cyrillic о
    '\u0440': 'p',  # Cyrillic р
    '\u0441': 'c',  # Cyrillic с
    '\u0443': 'y',  # Cyrillic у
    '\u0445': 'x',  # Cyrillic х
    '\u0455': 's',  # Cyrillic ѕ
    '\u0456': 'i',  # Cyrillic і
    '\u0458': 'j',  # Cyrillic ј
    '\u0501': 'd',  # Cyrillic ԁ
    '\u0261': 'g',  # Latin ɡ
    '\u03bd': 'v',  # Greek ν
    '\u03c9': 'w',  # Greek ω
    '\u03c1': 'p',  # Greek ρ
    '\u03c4': 't',  # Greek τ
    '\u03b9': 'i',  # Greek ι
}

# ── Phishing keywords ────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "update", "confirm", "account", "banking",
    "password", "credential", "authenticate", "wallet", "suspend",
    "suspended", "locked", "unusual", "activity", "unauthorized",
    "expire", "expired", "renew", "billing", "invoice", "payment",
    "kyc", "airdrop", "giveaway", "reward", "prize", "winner",
    "claim", "bonus", "free", "gift", "offer", "limited",
    "urgent", "immediate", "action", "required", "alert",
    "restore", "recover", "reset", "unlock", "reactivate",
]

# ── Abused TLDs ──────────────────────────────────────────────────────
ABUSED_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".buzz", ".click", ".loan", ".cam", ".icu", ".club",
    ".work", ".life", ".site", ".online", ".space", ".fun",
    ".rest", ".monster", ".surf", ".wang", ".trade", ".bid",
    ".win", ".racing", ".review", ".cricket", ".science",
    ".party", ".stream", ".download", ".accountant",
]

# ── URL shortener domains ────────────────────────────────────────────
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bl.ink", "lnkd.in",
    "shorte.st", "bc.vc", "v.gd", "rb.gy", "cutt.ly",
    "shorturl.at", "tiny.cc", "url.cn", "qr.ae",
]


@dataclass
class HeuristicResult:
    """Aggregated result of every heuristic check."""
    indicators: List[str] = field(default_factory=list)
    threat_score: float = 0.0
    brand_target: str = ""
    has_homoglyph: bool = False
    has_ip_host: bool = False
    keyword_hits: List[str] = field(default_factory=list)
    is_abused_tld: bool = False
    entropy: float = 0.0
    is_shortener: bool = False
    has_trick_symbols: bool = False
    has_suspicious_path: bool = False
    has_excessive_subdomains: bool = False
    uses_http: bool = False


# ── Helper functions ─────────────────────────────────────────────────

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return round(
        -sum((n / length) * math.log2(n / length) for n in freq.values()), 4
    )


def detect_homoglyphs(domain: str) -> Tuple[bool, str]:
    normalized = domain
    found = False
    for glyph, latin in HOMOGLYPHS.items():
        if glyph in domain:
            found = True
            normalized = normalized.replace(glyph, latin)
    return found, normalized


def detect_brand_spoofing(domain: str, path: str) -> Tuple[str, float]:
    full = (domain + path).lower()
    for brand, legit in BRAND_TARGETS.items():
        if brand in domain:
            if not any(domain == d or domain.endswith("." + d) for d in legit):
                return brand, 30.0
        if brand in path.lower():
            if not any(domain == d or domain.endswith("." + d) for d in legit):
                return brand, 20.0
    return "", 0.0


# ── Main analysis entry point ────────────────────────────────────────

def analyze_url(url: str) -> HeuristicResult:
    """Run every heuristic check and return an aggregated result."""
    result = HeuristicResult()

    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url

    try:
        parsed = urlparse(unquote(url))
    except Exception:
        result.indicators.append("❌ Invalid URL format")
        result.threat_score = 50.0
        return result

    hostname = (parsed.hostname or "").lower()
    path     = parsed.path or ""
    scheme   = parsed.scheme or ""
    full_url = url.lower()
    score    = 0.0

    # 1. HTTP
    if scheme == "http":
        result.uses_http = True
        result.indicators.append("⚠️  Uses insecure HTTP (no SSL/TLS)")
        score += 10.0

    # 2. Direct IP
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        result.has_ip_host = True
        result.indicators.append(f"🔴 Direct IP address as hostname: {hostname}")
        score += 25.0

    # 3. Homoglyph / Punycode
    has_glyph, normalized = detect_homoglyphs(hostname)
    if has_glyph:
        result.has_homoglyph = True
        result.indicators.append(
            f"🔴 Homoglyph attack! '{hostname}' masquerades as '{normalized}'"
        )
        score += 30.0
    if hostname.startswith("xn--"):
        result.has_homoglyph = True
        result.indicators.append(f"⚠️  Punycode (IDN) domain: {hostname}")
        score += 15.0

    # 4. Brand spoofing
    brand, brand_score = detect_brand_spoofing(hostname, path)
    if brand:
        result.brand_target = brand
        result.indicators.append(
            f"🔴 Potential {brand.upper()} impersonation / spoofing"
        )
        score += brand_score

    # 5. Phishing keywords
    for kw in PHISHING_KEYWORDS:
        if kw in full_url:
            result.keyword_hits.append(kw)
    if result.keyword_hits:
        score += min(len(result.keyword_hits) * 5.0, 25.0)
        result.indicators.append(
            f"⚠️  Phishing keywords: {', '.join(result.keyword_hits[:8])}"
        )

    # 6. Abused TLDs
    for tld in ABUSED_TLDS:
        if hostname.endswith(tld):
            result.is_abused_tld = True
            result.indicators.append(f"⚠️  High-risk TLD: {tld}")
            score += 15.0
            break

    # 7. Shannon entropy
    base = hostname.split('.')[0] if '.' in hostname else hostname
    result.entropy = shannon_entropy(base)
    if result.entropy > 3.8:
        result.indicators.append(
            f"⚠️  High entropy ({result.entropy}) — possible DGA domain"
        )
        score += 15.0

    # 8. URL shortener
    for s in URL_SHORTENERS:
        if hostname == s or hostname.endswith("." + s):
            result.is_shortener = True
            result.indicators.append(f"⚠️  URL shortener: {s}")
            score += 10.0
            break

    # 9. Trick symbols
    try:
        after_scheme = url.split("//", 1)[1]
        if '@' in after_scheme.split('/')[0]:
            result.has_trick_symbols = True
            result.indicators.append("🔴 '@' in authority — credential-bypass trick")
            score += 20.0
    except IndexError:
        pass

    try:
        after_host = url.split("://", 1)[1]
        if '/' in after_host:
            path_part = after_host.split('/', 1)[1]
            if '//' in path_part:
                result.has_trick_symbols = True
                result.indicators.append("⚠️  Double-slash redirect in path")
                score += 10.0
    except IndexError:
        pass

    # 10. Excessive subdomains
    dot_count = hostname.count('.')
    if dot_count >= 3:
        result.has_excessive_subdomains = True
        result.indicators.append(
            f"⚠️  Excessive subdomains ({dot_count} dots)"
        )
        score += 10.0

    # 11. Suspicious path extensions
    for ext in [".php", ".asp", ".cgi", "wp-admin", "wp-login", ".exe", ".zip", ".scr"]:
        if ext in path.lower():
            result.has_suspicious_path = True
            result.indicators.append(f"⚠️  Suspicious path element: {ext}")
            score += 5.0
            break

    # 12. Very long URL
    if len(url) > 200:
        result.indicators.append(f"⚠️  Unusually long URL ({len(url)} chars)")
        score += 5.0

    result.threat_score = min(score, 100.0)

    if not result.indicators:
        result.indicators.append("✅ No suspicious indicators found")

    return result
