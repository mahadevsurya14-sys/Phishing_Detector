"""
analyzer.py — Core orchestrator that combines heuristics + vendor matrix
              (+ optional live VirusTotal API) into a single ScanResult.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from detector.heuristics import analyze_url, HeuristicResult
from detector.threat_vendors import evaluate_vendors, detection_summary, VendorVerdict
from detector.vt_api import scan_url as vt_scan, VTResult


@dataclass
class ScanResult:
    url: str = ""
    risk_score: float = 0.0
    risk_level: str = ""
    detection_ratio: str = ""
    flagged: int = 0
    total: int = 72
    indicators: List[str] = field(default_factory=list)
    vendors: List[VendorVerdict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    heuristic: Optional[HeuristicResult] = None
    vt_result: Optional[VTResult] = None
    source: str = "Offline Heuristic Engine"


def _risk_level(score: float) -> str:
    if score <= 14:
        return "CLEAN & SAFE ✅"
    if score <= 34:
        return "LOW RISK ⚠️"
    if score <= 64:
        return "SUSPICIOUS 🟡"
    return "MALICIOUS / PHISHING 🔴"


class PhishingAnalyzer:
    """High-level API — call .scan(url) and get a ScanResult."""

    def scan(
        self,
        url: str,
        api_key: str = "",
    ) -> ScanResult:
        # ── 1.  Heuristic analysis ───────────────────────────────
        heuristic = analyze_url(url)

        # ── 2.  Vendor matrix (offline simulation) ───────────────
        vendors  = evaluate_vendors(heuristic)
        summary  = detection_summary(vendors)
        flagged  = summary["Malicious"] + summary["Suspicious"]

        result = ScanResult(
            url=url,
            risk_score=round(heuristic.threat_score, 1),
            risk_level=_risk_level(heuristic.threat_score),
            detection_ratio=f"{flagged} / {len(vendors)}",
            flagged=flagged,
            total=len(vendors),
            indicators=heuristic.indicators,
            vendors=vendors,
            summary=summary,
            heuristic=heuristic,
            source="Offline Heuristic Engine (72 vendors simulated)",
        )

        # ── 3.  Live VirusTotal (if key provided) ────────────────
        if api_key:
            vt = vt_scan(url, api_key)
            result.vt_result = vt
            if vt.success:
                result.source = "VirusTotal API v3 (LIVE)"
                result.detection_ratio = vt.detection_ratio
                result.total = vt.total
                flagged_vt = vt.malicious + vt.suspicious
                result.flagged = flagged_vt
                if vt.total > 0:
                    result.risk_score = round(
                        (flagged_vt / vt.total) * 100, 1
                    )
                result.risk_level = _risk_level(result.risk_score)

        return result
