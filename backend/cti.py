"""
PhishGuard — CTI (Cyber Threat Intelligence)
Async checks against VirusTotal and URLHaus.
Both calls run concurrently via asyncio.gather with a 3-second timeout each.
Failures are caught silently and return an empty dict.
"""

from __future__ import annotations

import asyncio
import base64
import os

import httpx
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_TIMEOUT = 3.0
UH_TIMEOUT = 3.0


# ── VirusTotal ────────────────────────────────────────────────────────────────

async def check_virustotal(url: str, api_key: str = VIRUSTOTAL_API_KEY) -> dict:
    """
    GET https://www.virustotal.com/api/v3/urls/{url_id}
    Returns relevant analysis stats or {} on any failure / missing key.
    """
    if not api_key:
        return {"status": "no_api_key"}

    # VT requires URL encoded as base64 without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    try:
        async with httpx.AsyncClient(timeout=VT_TIMEOUT) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": api_key},
            )
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attrs.get("reputation", 0),
                    "status":     "ok",
                }
            return {"status": f"http_{response.status_code}"}
    except asyncio.TimeoutError:
        return {"status": "timeout"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


# ── URLHaus ───────────────────────────────────────────────────────────────────

async def check_urlhaus(url: str) -> dict:
    """
    POST https://urlhaus-api.abuse.ch/v1/url/  body: url=<url>
    Returns query result or {} on any failure.
    """
    try:
        async with httpx.AsyncClient(timeout=UH_TIMEOUT) as client:
            response = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "query_status": data.get("query_status"),
                    "threat":       data.get("threat"),
                    "url_status":   data.get("url_status"),
                    "date_added":   data.get("date_added"),
                    "tags":         data.get("tags") or [],
                    "status":       "ok",
                }
            return {"status": f"http_{response.status_code}"}
    except asyncio.TimeoutError:
        return {"status": "timeout"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


# ── Combined ──────────────────────────────────────────────────────────────────

async def get_cti(url: str) -> dict:
    """
    Run VirusTotal + URLHaus concurrently.
    Returns {"virustotal": dict, "urlhaus": dict}.
    """
    vt_result, uh_result = await asyncio.gather(
        check_virustotal(url),
        check_urlhaus(url),
        return_exceptions=False,
    )
    return {
        "virustotal": vt_result,
        "urlhaus":    uh_result,
    }
