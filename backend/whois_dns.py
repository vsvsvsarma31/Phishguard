"""
PhishGuard — WHOIS & DNS Forensics
All lookups have a 5-second timeout and return {} on failure.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone

import dns.resolver
import dns.exception
import whois


# ── helpers ───────────────────────────────────────────────────────────────────

def _coerce_date(value) -> str | None:
    """Normalise a WHOIS date (may be list, datetime, or string) to ISO string."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0]
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _age_days(creation_raw) -> int | None:
    """Return number of days since domain creation, or None."""
    if creation_raw is None:
        return None
    try:
        dt = creation_raw[0] if isinstance(creation_raw, list) else creation_raw
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt)
        # make timezone-aware if naive
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(tz=timezone.utc) - dt
        return delta.days
    except Exception:
        return None


# ── public API ────────────────────────────────────────────────────────────────

def get_whois(domain: str) -> dict:
    """
    Returns {registrar, creation_date, expiry_date, age_days, registrant_country}
    or {} on any failure / timeout.
    """
    try:
        socket.setdefaulttimeout(5)
        w = whois.whois(domain)
        return {
            "registrar":           getattr(w, "registrar", None),
            "creation_date":       _coerce_date(getattr(w, "creation_date", None)),
            "expiry_date":         _coerce_date(getattr(w, "expiration_date", None)),
            "age_days":            _age_days(getattr(w, "creation_date", None)),
            "registrant_country":  getattr(w, "country", None),
        }
    except Exception:
        return {}
    finally:
        socket.setdefaulttimeout(None)


def get_dns(domain: str) -> dict:
    """
    Returns {a_records, mx_records, ns_records, has_spf, has_dmarc}
    or {} on any failure / timeout.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0   # total query timeout

    def _query(qtype: str) -> list[str]:
        try:
            answers = resolver.resolve(domain, qtype)
            return [rdata.to_text() for rdata in answers]
        except Exception:
            return []

    a_records  = _query("A")
    mx_records = _query("MX")
    ns_records = _query("NS")
    txt_records = _query("TXT")

    txt_joined = " ".join(txt_records).lower()
    has_spf    = any("v=spf1" in t for t in txt_records)
    has_dmarc  = False

    # DMARC is at _dmarc.<domain>
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        has_dmarc = any("v=dmarc1" in r.to_text().lower() for r in dmarc_answers)
    except Exception:
        pass

    return {
        "a_records":  a_records,
        "mx_records": mx_records,
        "ns_records": ns_records,
        "has_spf":    has_spf,
        "has_dmarc":  has_dmarc,
    }
