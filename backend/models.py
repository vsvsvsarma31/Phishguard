"""
PhishGuard — Pydantic Schemas
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class WhoisInfo(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiry_date: Optional[str] = None
    age_days: Optional[int] = None
    registrant_country: Optional[str] = None


class DnsInfo(BaseModel):
    a_records: List[str] = []
    mx_records: List[str] = []
    ns_records: List[str] = []
    has_spf: bool = False
    has_dmarc: bool = False


class CtiResult(BaseModel):
    virustotal: Dict[str, Any] = {}
    urlhaus: Dict[str, Any] = {}


class AnalysisResult(BaseModel):
    url: str
    label: str
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    is_obfuscated: bool = False
    features: Dict[str, Any] = {}
    cti: CtiResult = Field(default_factory=CtiResult)
    whois_info: WhoisInfo = Field(default_factory=WhoisInfo)
    dns_info: DnsInfo = Field(default_factory=DnsInfo)
    typosquat_matches: List[str] = []
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AnalyzeRequest(BaseModel):
    url: str


class StatsResponse(BaseModel):
    total: int
    phishing_count: int
    benign_count: int
    defacement_count: int
    malware_count: int
    risk_distribution: Dict[str, int]  # "low"/"medium"/"high"/"critical"
