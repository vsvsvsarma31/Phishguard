"""
PhishGuard — Typosquatting Detection
Compares an input domain against the TOP_BRANDS list using Levenshtein distance.
Returns brand names where distance <= 2 and the input domain is NOT an exact match.
"""

from __future__ import annotations

import Levenshtein

TOP_BRANDS: list[str] = [
    "google", "facebook", "apple", "microsoft", "amazon",
    "paypal", "netflix", "twitter", "instagram", "linkedin",
    "youtube", "yahoo", "reddit", "wikipedia", "ebay",
    "github", "dropbox", "spotify", "zoom", "slack",
    "adobe", "salesforce", "shopify", "wordpress", "twitch",
    "tiktok", "pinterest", "snapchat", "discord", "whatsapp",
    "office", "outlook", "skype", "bing", "live",
    "bankofamerica", "chase", "wellsfargo", "citibank", "capitalone",
    "americanexpress", "visa", "mastercard", "hsbc", "barclays",
    "steam", "roblox", "cloudflare", "godaddy", "namecheap",
]

_LEVENSHTEIN_THRESHOLD = 2


def detect_typosquatting(domain: str) -> list[str]:
    """
    Compare `domain` (e.g. "paypa1") against TOP_BRANDS.

    Parameters
    ----------
    domain : str
        The registrable domain portion only (no TLD, no subdomain).
        E.g. for "secure-paypal-login.tk" pass "secure-paypal-login" or
        the caller may strip TLD first.

    Returns
    -------
    list[str]
        Brand names where Levenshtein(domain, brand) <= 2
        and domain != brand (exact match is not a typosquat).
    """
    domain_lower = domain.lower().strip()
    matches: list[str] = []
    for brand in TOP_BRANDS:
        if domain_lower == brand:
            continue  # exact match — legitimate
        dist = Levenshtein.distance(domain_lower, brand)
        if dist <= _LEVENSHTEIN_THRESHOLD:
            matches.append(brand)
    return matches
