"""
PhishGuard — FastAPI Application

Endpoints
---------
POST /analyze  — full URL analysis (ML + CTI + WHOIS + DNS + typosquat + obfuscation)
GET  /history  — last 500 AnalysisResult entries (in-memory)
GET  /stats    — aggregate counts and risk distribution
GET  /health   — liveness probe

Startup: ML model + label encoder loaded once into app.state.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections import deque
from datetime import datetime
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

# ── project root on sys.path ─────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# ── internal imports ──────────────────────────────────────────────────────────
from phishguard.backend.models import (  # noqa: E402
    AnalysisResult,
    AnalyzeRequest,
    CtiResult,
    DnsInfo,
    StatsResponse,
    WhoisInfo,
)
from phishguard.backend.cti import get_cti  # noqa: E402
from phishguard.backend.whois_dns import get_dns, get_whois  # noqa: E402
from phishguard.backend.typosquat import detect_typosquatting  # noqa: E402
from phishguard.backend.obfuscation import decode_url  # noqa: E402

# ML imports (optional — graceful degradation if model not yet trained)
try:
    import joblib
    import numpy as np
    from phishguard.ml.features import extract_features, FEATURE_NAMES
    from phishguard.ml.predict import _is_safelisted   # safelist override
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False
    def _is_safelisted(url, age_days=None): return False  # type: ignore[misc]

# ── constants ─────────────────────────────────────────────────────────────────

MODEL_PATH = os.path.join(_HERE, "..", "ml", "model.pkl")
LE_PATH    = os.path.join(_HERE, "..", "ml", "label_encoder.pkl")
HISTORY_MAXLEN = 500

# ── app factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard API",
    description="Real-time phishing URL analysis with ML, CTI, WHOIS/DNS, and typosquatting detection.",
    version="1.0.0",
)

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory history ring buffer
_history: deque[AnalysisResult] = deque(maxlen=HISTORY_MAXLEN)


# ── startup: load ML model once ───────────────────────────────────────────────

@app.on_event("startup")
def _load_model():
    app.state.model = None
    app.state.label_encoder = None
    app.state.ml_ready = False

    if not _ML_AVAILABLE:
        print("[startup] ML libraries not available — skipping model load.")
        return

    if not os.path.exists(MODEL_PATH):
        print(f"[startup] Model not found at {MODEL_PATH} — run train.py first.")
        return

    if not os.path.exists(LE_PATH):
        print(f"[startup] Label encoder not found at {LE_PATH}.")
        return

    try:
        app.state.model         = joblib.load(MODEL_PATH)
        app.state.label_encoder = joblib.load(LE_PATH)
        app.state.ml_ready      = True
        classes = list(app.state.label_encoder.classes_)
        print(f"[startup] Model loaded — classes: {classes}")
    except Exception as exc:
        print(f"[startup] Failed to load model: {exc}")


# ── risk score computation ────────────────────────────────────────────────────

def _compute_risk_score(
    label: str,
    confidence: float,
    cti: dict,
    age_days: int | None,
    typosquat_matches: list[str],
) -> float:
    """
    risk_score = confidence*0.5 + cti_hit*0.3 + age_penalty*0.1 + typosquat_hit*0.1

    All components clamped to [0, 1] individually before weighting.
    Final score clamped to [0, 1].
    """
    # Component 1: model confidence (only harmful labels count fully)
    harmful_labels = {"phishing", "malware", "defacement"}
    ml_component = confidence if label in harmful_labels else confidence * 0.05

    # Component 2: CTI hit
    cti_hit = 0.0
    vt = cti.get("virustotal", {})
    uh = cti.get("urlhaus", {})
    vt_malicious = vt.get("malicious", 0)
    if isinstance(vt_malicious, (int, float)) and vt_malicious > 0:
        cti_hit = min(vt_malicious / 10.0, 1.0)      # scale: 10 engines = 1.0
    if uh.get("url_status") == "online":
        cti_hit = max(cti_hit, 0.9)
    if uh.get("query_status") == "is_listed":
        cti_hit = max(cti_hit, 0.7)

    # Component 3: age penalty (new domain ≤ 90 days = 1.0, ≤ 365 = 0.5)
    age_penalty = 0.0
    if age_days is not None:
        if age_days <= 30:
            age_penalty = 1.0
        elif age_days <= 90:
            age_penalty = 0.8
        elif age_days <= 180:
            age_penalty = 0.5
        elif age_days <= 365:
            age_penalty = 0.2

    # Component 4: typosquatting
    typosquat_hit = 1.0 if typosquat_matches else 0.0

    score = (
        ml_component * 0.5
        + cti_hit     * 0.3
        + age_penalty * 0.1
        + typosquat_hit * 0.1
    )
    return round(min(max(score, 0.0), 1.0), 4)


# ── helpers ───────────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> str:
    """Return the registrable domain+TLD from a URL, stripping 'www.'."""
    try:
        host = urlparse(url).hostname or url
        if host.lower().startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return url


def _domain_part_only(domain: str) -> str:
    """Strip TLD: 'paypal.com' -> 'paypal'."""
    parts = domain.rsplit(".", 1)
    return parts[0] if len(parts) == 2 else domain


def _ml_predict(request: Request, url: str, age_days: int | None = None) -> tuple[str, float, dict]:
    """
    Run ML inference. Returns (label, confidence, features_dict).
    Falls back to ("unknown", 0.0, {}) if model not loaded.
    Applies post-prediction Alexa safelist override when applicable.
    """
    if not getattr(request.app.state, "ml_ready", False):
        return "unknown", 0.0, {}

    try:
        features = extract_features(url)
        X = np.array([features[k] for k in FEATURE_NAMES], dtype=np.float32).reshape(1, -1)

        model = request.app.state.model
        le    = request.app.state.label_encoder

        proba    = model.predict_proba(X)[0]
        pred_idx = int(np.argmax(proba))
        label    = le.inverse_transform([pred_idx])[0]
        confidence = float(proba[pred_idx])

        # ── post-prediction Alexa safelist override ───────────────────────────
        if label != "benign" and _is_safelisted(url, age_days):
            print(
                f"[backend] OVERRIDE: {url!r} raw={label}@{confidence:.2%} "
                f"-> benign (Alexa safelist, age_days={age_days})"
            )
            label      = "benign"
            confidence = 1.0   # rule-based certainty

        return label, confidence, features
    except Exception as exc:
        print(f"[ml_predict] Error: {exc}")
        return "unknown", 0.0, {}


# ── endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "ml_ready": getattr(app.state, "ml_ready", False),
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(req: AnalyzeRequest, request: Request):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL must not be empty.")

    # ── 1. Obfuscation decode ─────────────────────────────────────────────────
    obf = decode_url(url)
    decoded_url   = obf["decoded"]
    is_obfuscated = obf["was_obfuscated"]

    # Use decoded URL for all downstream analysis
    analysis_url = decoded_url

    # ── 2. Domain extraction for WHOIS / DNS / typosquat ─────────────────────
    domain      = _extract_domain(analysis_url)
    domain_part = _domain_part_only(domain)

    # ── 3. Async: CTI + WHOIS/DNS concurrently (before ML so age_days is available) ──
    cti_raw, whois_raw, dns_raw = await asyncio.gather(
        get_cti(analysis_url),
        asyncio.to_thread(get_whois, domain),
        asyncio.to_thread(get_dns, domain),
    )

    # ── 4. ML inference (with age_days for safelist override) ─────────────────
    age_days = whois_raw.get("age_days")
    label, confidence, features = _ml_predict(request, analysis_url, age_days=age_days)

    # ── 5. Typosquatting (sync, cheap) ───────────────────────────────────────
    typosquat_matches = detect_typosquatting(domain_part)

    # ── 6. Build sub-models ───────────────────────────────────────────────────
    cti_model = CtiResult(
        virustotal=cti_raw.get("virustotal", {}),
        urlhaus=cti_raw.get("urlhaus", {}),
    )

    whois_model = WhoisInfo(
        registrar=whois_raw.get("registrar"),
        creation_date=str(whois_raw.get("creation_date")) if whois_raw.get("creation_date") else None,
        expiry_date=str(whois_raw.get("expiry_date")) if whois_raw.get("expiry_date") else None,
        age_days=whois_raw.get("age_days"),
        registrant_country=whois_raw.get("registrant_country"),
    )

    dns_model = DnsInfo(
        a_records=dns_raw.get("a_records", []),
        mx_records=dns_raw.get("mx_records", []),
        ns_records=dns_raw.get("ns_records", []),
        has_spf=dns_raw.get("has_spf", False),
        has_dmarc=dns_raw.get("has_dmarc", False),
    )

    # ── 6. Risk score (uses updated label post-override) ─────────────────────
    risk_score = _compute_risk_score(
        label=label,
        confidence=confidence,
        cti=cti_raw,
        age_days=whois_raw.get("age_days"),
        typosquat_matches=typosquat_matches,
    )

    # ── 8. Assemble result ────────────────────────────────────────────────────
    # Convert numpy types to standard python types for JSON serialization
    serializable_features = {k: float(v) if hasattr(v, 'item') else v for k, v in features.items()}

    result = AnalysisResult(
        url=url,                           # original URL as submitted
        label=label,
        confidence=round(float(confidence), 6),
        risk_score=float(risk_score),
        is_obfuscated=is_obfuscated,
        features=serializable_features,
        cti=cti_model,
        whois_info=whois_model,
        dns_info=dns_model,
        typosquat_matches=typosquat_matches,
        timestamp=datetime.utcnow(),
    )

    _history.appendleft(result)
    return result


@app.get("/history", response_model=list[AnalysisResult])
async def history():
    return list(_history)


@app.get("/stats", response_model=StatsResponse)
async def stats():
    items = list(_history)
    total = len(items)

    counts: dict[str, int] = {}
    risk_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}

    for item in items:
        counts[item.label] = counts.get(item.label, 0) + 1
        rs = item.risk_score
        if rs < 0.25:
            risk_dist["low"] += 1
        elif rs < 0.50:
            risk_dist["medium"] += 1
        elif rs < 0.75:
            risk_dist["high"] += 1
        else:
            risk_dist["critical"] += 1

    return StatsResponse(
        total=total,
        phishing_count=counts.get("phishing", 0),
        benign_count=counts.get("benign", 0),
        defacement_count=counts.get("defacement", 0),
        malware_count=counts.get("malware", 0),
        risk_distribution=risk_dist,
    )


# ── entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
