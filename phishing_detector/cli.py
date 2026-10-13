#!/usr/bin/env python3
"""
cli.py — Rich-powered interactive terminal scanner.

Usage:
    python cli.py                                          # interactive mode
    python cli.py "http://evil.xyz/login"                  # single scan
    python cli.py "http://evil.xyz/login" --all            # show all 72 vendors
    python cli.py "http://evil.xyz/login" --api-key KEY    # live VirusTotal
"""
from __future__ import annotations

import argparse
import io
import os
import sys
import time

# ── Force UTF-8 on Windows to avoid cp1252 emoji crashes ─────────────
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich import box

from detector.analyzer import PhishingAnalyzer, ScanResult


console = Console(force_terminal=True, legacy_windows=False)

# ── colour helpers ────────────────────────────────────────────────────

_STATUS_STYLE = {
    "Malicious":  "bold red",
    "Suspicious": "bold yellow",
    "Clean":      "bold green",
    "Undetected": "dim",
}


def _score_colour(score: float) -> str:
    if score <= 14:
        return "green"
    if score <= 34:
        return "yellow"
    if score <= 64:
        return "dark_orange"
    return "red"


# ── display functions ─────────────────────────────────────────────────

def _print_banner():
    banner = r"""
[bold cyan]
  ____  _     _     _     _               ____       _            _
 |  _ \| |__ (_)___| |__ (_)_ __   __ _  |  _ \  ___| |_ ___  ___| |_ ___  _ __
 | |_) | '_ \| / __| '_ \| | '_ \ / _` | | | | |/ _ \ __/ _ \/ __| __/ _ \| '__|
 |  __/| | | | \__ \ | | | | | | | (_| | | |_| |  __/ ||  __/ (__| || (_) | |
 |_|   |_| |_|_|___/_| |_|_|_| |_|\__, | |____/ \___|\__\___|\___|\__\___/|_|
                                   |___/
[/bold cyan]
[dim]URL Threat & Risk Analyzer — 72 Security Engines[/dim]
"""
    console.print(banner)


def display_result(result: ScanResult, show_all: bool = False):
    """Pretty-print a full scan report."""

    colour = _score_colour(result.risk_score)

    # ── header panel ──────────────────────────────────────────────
    header = Text()
    header.append("🔗 URL:  ", style="bold")
    header.append(result.url + "\n", style="underline cyan")
    header.append("📡 Source:  ", style="bold")
    header.append(result.source + "\n\n", style="dim")
    header.append(f"Detection Ratio:  ", style="bold")
    header.append(f"{result.detection_ratio}\n", style=f"bold {colour}")
    header.append(f"Risk Score:       ", style="bold")
    header.append(f"{result.risk_score}%\n", style=f"bold {colour}")
    header.append(f"Verdict:          ", style="bold")
    header.append(f"{result.risk_level}\n", style=f"bold {colour}")

    console.print(Panel(header, title="[bold]🛡️  Scan Report[/bold]", border_style=colour, box=box.DOUBLE))

    # ── indicators ────────────────────────────────────────────────
    ind_table = Table(title="🔍 Threat Indicators", box=box.ROUNDED, show_lines=True)
    ind_table.add_column("#", justify="right", style="dim", width=4)
    ind_table.add_column("Indicator", style="white")
    for i, ind in enumerate(result.indicators, 1):
        ind_table.add_row(str(i), ind)
    console.print(ind_table)

    # ── summary bar ───────────────────────────────────────────────
    sm = result.summary
    console.print()
    console.print(
        f"  [bold red]■ Malicious: {sm.get('Malicious',0)}[/]  "
        f"[bold yellow]■ Suspicious: {sm.get('Suspicious',0)}[/]  "
        f"[bold green]■ Clean: {sm.get('Clean',0)}[/]  "
        f"[dim]■ Undetected: {sm.get('Undetected',0)}[/]"
    )
    console.print()

    # ── vendor table ──────────────────────────────────────────────
    vendors_to_show = result.vendors if show_all else [
        v for v in result.vendors if v.status in ("Malicious", "Suspicious")
    ]

    if vendors_to_show:
        title = "All 72 Security Vendors" if show_all else "Flagged Vendors (use --all to see all 72)"
        v_table = Table(title=f"🏢 {title}", box=box.SIMPLE_HEAVY)
        v_table.add_column("#",        justify="right", style="dim", width=4)
        v_table.add_column("Vendor",   style="cyan",   min_width=28)
        v_table.add_column("Category", style="magenta", min_width=16)
        v_table.add_column("Status",   min_width=12)

        for i, v in enumerate(vendors_to_show, 1):
            style = _STATUS_STYLE.get(v.status, "")
            v_table.add_row(str(i), v.name, v.category, Text(v.status, style=style))

        console.print(v_table)
    else:
        console.print("[green]  ✅  No vendors flagged this URL.[/green]")

    console.print()


# ── scanning animation ────────────────────────────────────────────────

def run_scan(url: str, api_key: str = "", show_all: bool = False):
    analyzer = PhishingAnalyzer()

    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold cyan]Scanning with 72 security engines…"),
        BarColumn(bar_width=40),
        transient=True,
    ) as progress:
        task = progress.add_task("scan", total=100)
        for pct in range(0, 101, 5):
            progress.update(task, completed=pct)
            time.sleep(0.04)

    result = analyzer.scan(url, api_key=api_key)
    display_result(result, show_all=show_all)


# ── entry point ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🛡️  Phishing Detector — URL Threat & Risk Analyzer",
    )
    parser.add_argument("url", nargs="?", help="URL to scan")
    parser.add_argument("--all", action="store_true", help="Show all 72 vendors")
    parser.add_argument("--api-key", default="", help="VirusTotal API v3 key")
    args = parser.parse_args()

    _print_banner()

    if args.url:
        run_scan(args.url, api_key=args.api_key, show_all=args.all)
    else:
        console.print("[bold green]Interactive Mode[/bold green] — type a URL to scan, or 'quit' to exit.\n")
        while True:
            try:
                url = console.input("[bold cyan]Enter URL ▸ [/bold cyan]").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not url or url.lower() in ("quit", "exit", "q"):
                console.print("[dim]Bye! 👋[/dim]")
                break
            run_scan(url, api_key=args.api_key, show_all=args.all)


if __name__ == "__main__":
    main()
