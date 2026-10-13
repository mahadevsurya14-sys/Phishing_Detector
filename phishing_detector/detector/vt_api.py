"""
vt_api.py — Official VirusTotal API v3 integration.

Submits a URL for scanning and retrieves the analysis report.
Falls back gracefully when no API key is provided.
"""
from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


VT_BASE = "https://www.virustotal.com/api/v3"


@dataclass
class VTResult:
    """Parsed result from VirusTotal API."""
    success: bool = False
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0
    detection_ratio: str = ""
    error: str = ""
    vendors: List[dict] = field(default_factory=list)


def scan_url(url: str, api_key: str, timeout: int = 60) -> VTResult:
    """
    Submit *url* to VirusTotal and poll for results.

    Returns a VTResult with per-vendor breakdown.
    """
    if not HAS_REQUESTS:
        return VTResult(error="'requests' library not installed. pip install requests")

    if not api_key:
        return VTResult(error="No API key provided")

    headers = {"x-apikey": api_key}

    # Step 1 — submit URL for scanning
    try:
        resp = requests.post(
            f"{VT_BASE}/urls",
            headers=headers,
            data={"url": url},
            timeout=15,
        )
        if resp.status_code == 401:
            return VTResult(error="Invalid VirusTotal API key (401 Unauthorized)")
        if resp.status_code == 429:
            return VTResult(error="VirusTotal API rate limit reached — try again later")
        resp.raise_for_status()
    except requests.RequestException as exc:
        return VTResult(error=f"VirusTotal API request failed: {exc}")

    # Step 2 — get analysis ID & poll
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    analysis_url = f"{VT_BASE}/urls/{url_id}"

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(analysis_url, headers=headers, timeout=15)
            if r.status_code == 200:
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                results = data.get("last_analysis_results", {})

                vt = VTResult(success=True)
                vt.malicious  = stats.get("malicious", 0)
                vt.suspicious = stats.get("suspicious", 0)
                vt.harmless   = stats.get("harmless", 0)
                vt.undetected = stats.get("undetected", 0)
                vt.total      = sum(stats.values())
                flagged       = vt.malicious + vt.suspicious
                vt.detection_ratio = f"{flagged} / {vt.total}"

                for engine, info in results.items():
                    vt.vendors.append({
                        "name":     engine,
                        "category": info.get("engine_name", engine),
                        "status":   info.get("category", "undetected").capitalize(),
                    })

                return vt
        except requests.RequestException:
            pass

        time.sleep(3)

    return VTResult(error="VirusTotal analysis timed out")
