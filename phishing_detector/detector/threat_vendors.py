"""
threat_vendors.py — 72 simulated security-vendor detection matrix.

Each vendor has a name, a specialty category, and a sensitivity threshold.
The heuristic threat_score is compared against each vendor's threshold to
determine its verdict: Malicious / Suspicious / Clean / Undetected.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List

from detector.heuristics import HeuristicResult


@dataclass
class VendorVerdict:
    name: str
    category: str
    status: str          # Malicious | Suspicious | Clean | Undetected


# ── 72 security vendors ──────────────────────────────────────────────
# (name, category, base_threshold)
# Vendors with a LOWER threshold are stricter / more sensitive.
_VENDOR_DEFS: list[tuple[str, str, int]] = [
    ("Google Safebrowsing",      "Search Engine",     20),
    ("Kaspersky",                "Antivirus",         18),
    ("Bitdefender",              "Antivirus",         22),
    ("ESET",                     "Antivirus",         24),
    ("Avira",                    "Antivirus",         20),
    ("Sophos",                   "Antivirus",         22),
    ("Norton / Symantec",        "Antivirus",         25),
    ("McAfee",                   "Antivirus",         26),
    ("Trend Micro",              "Antivirus",         23),
    ("Palo Alto Networks",       "Firewall",          18),
    ("Fortinet",                 "Firewall",          20),
    ("CrowdStrike Falcon",       "EDR",               16),
    ("SentinelOne",              "EDR",               17),
    ("Microsoft Defender",       "Antivirus",         22),
    ("Avast",                    "Antivirus",         28),
    ("AVG",                      "Antivirus",         28),
    ("Comodo Valkyrie",          "Antivirus",         30),
    ("F-Secure",                 "Antivirus",         24),
    ("G Data",                   "Antivirus",         26),
    ("Malwarebytes",             "Anti-Malware",      22),
    ("Dr.Web",                   "Antivirus",         25),
    ("Emsisoft",                 "Anti-Malware",      20),
    ("NANO Antivirus",           "Antivirus",         32),
    ("Cyren",                    "Email Security",    24),
    ("OpenPhish",                "Phishing Feed",     15),
    ("PhishTank",                "Phishing Feed",     14),
    ("Netcraft",                 "Phishing Feed",     16),
    ("AutoShun",                 "Threat Intel",      30),
    ("AlienVault OTX",           "Threat Intel",      20),
    ("Sucuri SiteCheck",         "Web Security",      22),
    ("URLhaus / abuse.ch",       "Malware Feed",      18),
    ("Spamhaus DBL",             "Blacklist",         20),
    ("SURBL",                    "Blacklist",         22),
    ("Quttera",                  "Web Security",      28),
    ("Trustwave",                "Web Security",      26),
    ("Webroot BrightCloud",      "Cloud Intel",       24),
    ("Yandex Safebrowsing",      "Search Engine",     22),
    ("Baidu Antivirus",          "Antivirus",         35),
    ("Tencent",                  "Antivirus",         30),
    ("Ikarus",                   "Antivirus",         26),
    ("Bkav Pro",                 "Antivirus",         34),
    ("CMC Threat Intelligence",  "Threat Intel",      30),
    ("CyRadar",                  "Threat Intel",      28),
    ("DNS8 (Layer8)",            "DNS Security",      26),
    ("ESTsecurity",              "Antivirus",         28),
    ("Lionic",                   "Antivirus",         32),
    ("Rising",                   "Antivirus",         30),
    ("SafeDNS",                  "DNS Security",      26),
    ("Sangfor Engine Zero",      "Antivirus",         28),
    ("Acronis",                  "Backup/Security",   30),
    ("BitDefender Theta",        "Cloud Intel",       22),
    ("BlockList.de",             "Blacklist",         24),
    ("CRDF",                     "Threat Intel",      26),
    ("Criminal IP",              "Threat Intel",      20),
    ("Xcitium (ex-Comodo)",      "Antivirus",         28),
    ("CyberCrime Tracker",       "Threat Intel",      22),
    ("Heimdal Security",         "DNS Security",      24),
    ("Juniper Networks",         "Firewall",          26),
    ("K7 Antivirus",             "Antivirus",         30),
    ("Lumu",                     "Threat Intel",      22),
    ("MAX (SaintSecurity)",      "Antivirus",         32),
    ("Phishing Database",        "Phishing Feed",     16),
    ("Quick Heal",               "Antivirus",         28),
    ("Snort / Suricata",         "IDS/IPS",           24),
    ("Spam404",                  "Blacklist",         26),
    ("StopBadware / StopForumSpam", "Blacklist",      28),
    ("VX Vault",                 "Malware Feed",      20),
    ("Viettel Threat Intelligence", "Threat Intel",   26),
    ("ZeroCERT",                 "Threat Intel",      30),
    ("ZoneAlarm (Check Point)",  "Firewall",          22),
    ("Abusix",                   "Blacklist",         28),
    ("CleanBrowsing",            "DNS Security",      26),
]

assert len(_VENDOR_DEFS) == 72, f"Expected 72 vendors, got {len(_VENDOR_DEFS)}"


def evaluate_vendors(heuristic: HeuristicResult, seed: int | None = None) -> List[VendorVerdict]:
    """
    Map the heuristic threat_score onto each vendor's threshold to produce
    a list of 72 VendorVerdict objects.

    Logic per vendor:
      • score >= threshold        → Malicious
      • score >= threshold * 0.6  → Suspicious
      • score >  0 but below 0.6 → Clean (vendor checked, found nothing decisive)
      • score == 0                → Undetected (nothing to flag at all)

    A small deterministic jitter (±3) is applied per vendor so the matrix
    is not perfectly uniform — mirrors real-world engine disagreement.
    """
    rng = random.Random(seed if seed is not None else hash(str(heuristic.threat_score)))
    verdicts: list[VendorVerdict] = []

    for name, category, base_thresh in _VENDOR_DEFS:
        jitter   = rng.randint(-3, 3)
        thresh   = max(5, base_thresh + jitter)
        score    = heuristic.threat_score

        if score <= 0:
            status = "Undetected"
        elif score >= thresh:
            status = "Malicious"
        elif score >= thresh * 0.6:
            status = "Suspicious"
        else:
            status = "Clean"

        verdicts.append(VendorVerdict(name=name, category=category, status=status))

    return verdicts


def detection_summary(verdicts: List[VendorVerdict]) -> dict:
    """Return counts for each status bucket."""
    counts = {"Malicious": 0, "Suspicious": 0, "Clean": 0, "Undetected": 0}
    for v in verdicts:
        counts[v.status] = counts.get(v.status, 0) + 1
    return counts
