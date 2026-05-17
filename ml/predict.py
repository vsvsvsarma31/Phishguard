"""
PhishGuard — Inference
predict(url: str) -> {"label": str, "confidence": float, "features": dict, ...}

* Model + encoder loaded once at module import (module-level singleton).
* Inference path: pure dict/numpy — no pandas.
* In dev mode (PHISHGUARD_DEV=1) asserts latency < 500 ms.
* Post-prediction override: domains on the Alexa/Tranco top-1000 safelist
  with WHOIS age > 365 days are always forced to 'benign', regardless of
  the model's raw prediction.  This prevents well-known domains like
  google.com / youtube.com from being flagged as phishing.
"""

from __future__ import annotations

import os
import sys
import time
import joblib
import numpy as np
from urllib.parse import urlparse

# ── make project root importable when run directly ────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from phishguard.ml.features import extract_features, FEATURE_NAMES  # noqa: E402

# ── paths ─────────────────────────────────────────────────────────────────────

MODEL_PATH = os.path.join(_HERE, "model.pkl")
LE_PATH    = os.path.join(_HERE, "label_encoder.pkl")

# ── singleton cache ───────────────────────────────────────────────────────────

_model = None
_le    = None
_ready = False

DEV_MODE = os.getenv("PHISHGUARD_DEV", "0") == "1"
LATENCY_LIMIT_MS = 500.0


# ── Alexa / Tranco top-1000 safelist ─────────────────────────────────────────
# Curated list of globally trusted apex domains.
# URLs whose registrable domain is in this set AND whose WHOIS age > 365 days
# are overridden to 'benign' regardless of model output.
# Extend this list as needed; keeping it to well-known brands avoids false safety.

ALEXA_TOP_1000: frozenset[str] = frozenset({
    # Search & general
    "google.com", "bing.com", "yahoo.com", "baidu.com", "duckduckgo.com",
    "ask.com", "aol.com", "search.com",
    # Video / media
    "youtube.com", "netflix.com", "twitch.tv", "vimeo.com", "dailymotion.com",
    "tiktok.com", "hulu.com", "disneyplus.com", "primevideo.com",
    # Social
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "reddit.com", "pinterest.com", "tumblr.com", "snapchat.com", "discord.com",
    "whatsapp.com", "telegram.org", "signal.org",
    # Tech / dev
    "github.com", "gitlab.com", "stackoverflow.com", "microsoft.com",
    "apple.com", "amazon.com", "aws.amazon.com", "azure.microsoft.com",
    "cloudflare.com", "digitalocean.com", "heroku.com", "vercel.com",
    "netlify.com", "wordpress.com", "wordpress.org", "wix.com",
    # Commerce / finance
    "ebay.com", "etsy.com", "shopify.com", "aliexpress.com", "alibaba.com",
    "paypal.com", "stripe.com", "visa.com", "mastercard.com", "amex.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
    "hsbc.com", "barclays.com", "robinhood.com", "coinbase.com",
    # Productivity / cloud
    "dropbox.com", "drive.google.com", "docs.google.com", "office.com",
    "notion.so", "slack.com", "zoom.us", "teams.microsoft.com",
    "trello.com", "asana.com", "atlassian.com", "jira.com", "confluence.com",
    "salesforce.com", "hubspot.com", "zendesk.com",
    # News / info
    "wikipedia.org", "nytimes.com", "bbc.com", "cnn.com", "reuters.com",
    "theguardian.com", "bloomberg.com", "forbes.com", "wsj.com",
    # CDN / infra (often appear benign)
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    # Misc trusted
    "adobe.com", "canva.com", "figma.com", "spotify.com", "soundcloud.com",
    "booking.com", "airbnb.com", "uber.com", "lyft.com",
    "medium.com", "substack.com", "ghost.io",
    "npmjs.com", "pypi.org", "crates.io", "rubygems.org",
    "docker.com", "kubernetes.io", "tensorflow.org", "pytorch.org",
})


def _registrable_domain(url: str) -> str:
    """
    Extract the registrable domain (apex domain + TLD) from a URL.
    e.g. 'https://www.google.com/search' -> 'google.com'
    """
    try:
        host = urlparse(url).hostname or url
        host = host.lower()
        if host.startswith("www."):
            host = host[4:]
        # naive: last two parts (works for simple TLDs; good enough for safelist)
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return ""


def _is_safelisted(url: str, age_days: int | None = None) -> bool:
    """
    Return True if the URL's registrable domain is in the Alexa safelist
    AND (age_days is None OR age_days > 365).
    The age_days check is skipped when WHOIS data is unavailable (None),
    because the safelist itself is the trust anchor.
    """
    domain = _registrable_domain(url)
    in_list = domain in ALEXA_TOP_1000
    if not in_list:
        return False
    # If we have age info, require the domain to be established
    if age_days is not None and age_days <= 365:
        return False
    return True


# ── singleton loader ──────────────────────────────────────────────────────────

def _load_once() -> bool:
    """Load model + encoder into module-level cache. Idempotent."""
    global _model, _le, _ready
    if _ready:
        return True
    if not os.path.exists(MODEL_PATH):
        print(f"[predict] WARN: model not found at {MODEL_PATH}")
        return False
    if not os.path.exists(LE_PATH):
        print(f"[predict] WARN: label encoder not found at {LE_PATH}")
        return False
    try:
        _model = joblib.load(MODEL_PATH)
        _le    = joblib.load(LE_PATH)
        _ready = True
        print(f"[predict] Model loaded ({len(_le.classes_)} classes: {list(_le.classes_)})")
        return True
    except Exception as e:
        print(f"[predict] WARN: failed to load artefacts: {e}")
        return False


# Load at import time
_load_once()


# ── public API ────────────────────────────────────────────────────────────────

def predict(url: str, age_days: int | None = None) -> dict:
    """
    Parameters
    ----------
    url      : str
    age_days : int | None
        WHOIS domain age in days.  Passed to the safelist check.
        If None, the safelist override still applies (age check skipped).

    Returns
    -------
    {
        "label":          str,    # e.g. "phishing"
        "confidence":     float,  # max class probability [0, 1]
        "features":       dict,   # raw feature dict from extract_features()
        "probabilities": {cls: float},
        "latency_ms":     float,
        "override":       bool,   # True if post-prediction safelist override fired
    }
    """
    if not _ready and not _load_once():
        return {
            "label": "unknown",
            "confidence": 0.0,
            "features": {},
            "probabilities": {},
            "latency_ms": 0.0,
            "override": False,
            "error": "Model not loaded",
        }

    t0 = time.perf_counter()

    # ── feature extraction (pure dict) ────────────────────────────────────────
    features: dict = extract_features(url)

    # ── numpy array, no pandas ────────────────────────────────────────────────
    X = np.array([[features[k] for k in FEATURE_NAMES]], dtype=np.float32)

    # ── inference ─────────────────────────────────────────────────────────────
    proba: np.ndarray = _model.predict_proba(X)[0]   # shape (n_classes,)
    pred_idx: int = int(np.argmax(proba))
    label: str = _le.inverse_transform([pred_idx])[0]
    confidence: float = float(proba[pred_idx])

    probabilities = {
        cls: round(float(p), 6)
        for cls, p in zip(_le.classes_, proba)
    }

    # ── post-prediction override: Alexa safelist ───────────────────────────────
    override = False
    if label != "benign" and _is_safelisted(url, age_days):
        original_label = label
        original_conf  = confidence
        label      = "benign"
        confidence = 1.0   # rule-based certainty
        override   = True
        print(
            f"[predict] OVERRIDE fired for {url!r}  "
            f"({original_label} @ {original_conf:.2%} -> benign @ 100.00%)  "
            f"domain={_registrable_domain(url)!r} is in Alexa safelist"
        )

    latency_ms = (time.perf_counter() - t0) * 1000.0

    # ── dev-mode latency assertion ────────────────────────────────────────────
    if DEV_MODE:
        assert latency_ms < LATENCY_LIMIT_MS, (
            f"Inference latency {latency_ms:.2f} ms exceeds {LATENCY_LIMIT_MS} ms limit"
        )

    return {
        "label":         label,
        "confidence":    round(confidence, 6),
        "features":      features,
        "probabilities": probabilities,
        "latency_ms":    round(latency_ms, 3),
        "override":      override,
    }


def reload():
    """Force-reload model and encoder from disk."""
    global _model, _le, _ready
    _model = _le = None
    _ready = False
    return _load_once()


# ── entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_urls = [
        # Known benign (should ALL return benign after override)
        "https://www.google.com",
        "https://www.youtube.com",
        "https://www.github.com",
        "https://www.microsoft.com",
        "https://www.amazon.com",
        # Known phishing / malicious
        "http://payp4l-secure-login.tk/verify?user=1&token=abc",
        "http://192.168.1.1/admin/cmd.exe?download=mal.zip",
        "http://secure-login-paypal.com.verify.login/secure/index.php?user=%41%42%43",
        "https://faceb00k-login.cf/update/credentials",
        "https://github.com/openai/gpt-4",   # benign with path
    ]

    print("=" * 70)
    print("PhishGuard — predict.py sanity test (includes safelist override)")
    print("=" * 70)

    for url in test_urls:
        result = predict(url)
        override_tag = "  [OVERRIDE]" if result["override"] else ""
        print(
            f"\n[{result['label'].upper():12s}] conf={result['confidence']:.2%}"
            f"  lat={result['latency_ms']:.1f}ms{override_tag}"
            f"\n  {url}"
        )
        print("  Probabilities:", {k: f"{v:.3%}" for k, v in result["probabilities"].items()})
