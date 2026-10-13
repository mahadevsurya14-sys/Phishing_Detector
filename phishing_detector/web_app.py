#!/usr/bin/env python3
"""
web_app.py — Flask web dashboard (VirusTotal-style dark UI).

Run:   python web_app.py
Open:  http://127.0.0.1:5000
"""
from __future__ import annotations

import os, sys
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import json
from flask import Flask, render_template, request, jsonify

from detector.analyzer import PhishingAnalyzer

app = Flask(__name__)
analyzer = PhishingAnalyzer()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data    = request.get_json(force=True)
    url     = data.get("url", "").strip()
    api_key = data.get("api_key", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = analyzer.scan(url, api_key=api_key)

    return jsonify({
        "url":              result.url,
        "risk_score":       result.risk_score,
        "risk_level":       result.risk_level,
        "detection_ratio":  result.detection_ratio,
        "flagged":          result.flagged,
        "total":            result.total,
        "indicators":       result.indicators,
        "source":           result.source,
        "summary":          result.summary,
        "vendors": [
            {"name": v.name, "category": v.category, "status": v.status}
            for v in result.vendors
        ],
    })


if __name__ == "__main__":
    print("\n🛡️  Phishing Detector Web Dashboard")
    print("    ➜  http://127.0.0.1:5000\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
