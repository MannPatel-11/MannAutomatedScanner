#!/usr/bin/env python3
"""
MannAutomatedScanner — Python Terminal UI
Directly imports and runs the scanner core (no Flask server required).

Usage:
    python scanner_ui.py                   # interactive prompt
    python scanner_ui.py https://site.com  # direct scan
    python scanner_ui.py --demo            # show demo data without scanning
"""

import sys
import io
from datetime import datetime, timezone

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from rich.rule import Rule

# ── Import scanner core directly (no Flask needed) ──
try:
    from MannAutomatedScanner import scan
except ImportError as e:
    print(f"ERROR: Could not import MannAutomatedScanner.py — {e}")
    sys.exit(1)

# ─────────────────────────────────────────────
#  Console  (UTF-8 forced to avoid Windows cp1252 crash)
# ─────────────────────────────────────────────
console = Console(
    file=io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if hasattr(sys.stdout, "buffer") else sys.stdout
)

# ─────────────────────────────────────────────
#  Demo data  (used only with --demo flag)
# ─────────────────────────────────────────────
DEMO_RESULT = {
    "url": "https://demo.example.com",
    "scanned_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "status_code": 200,
    "score": 3,
    "max_score": 7,
    "error": None,
    "header_checks": [
        {"name": "Content-Security-Policy",   "status": "fail", "severity": "high",   "value": None,                               "recommendation": "Add a Content-Security-Policy header to restrict allowed content sources and mitigate XSS attacks."},
        {"name": "Strict-Transport-Security", "status": "pass", "severity": "high",   "value": "max-age=31536000; includeSubDomains", "recommendation": ""},
        {"name": "X-Frame-Options",           "status": "fail", "severity": "medium", "value": None,                               "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking."},
        {"name": "X-Content-Type-Options",    "status": "pass", "severity": "medium", "value": "nosniff",                          "recommendation": ""},
        {"name": "Referrer-Policy",           "status": "fail", "severity": "low",    "value": None,                               "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin."},
        {"name": "Permissions-Policy",        "status": "fail", "severity": "low",    "value": None,                               "recommendation": "Add a Permissions-Policy header to restrict browser API access."},
        {"name": "Cache-Control",             "status": "pass", "severity": "low",    "value": "no-store, no-cache",               "recommendation": ""},
    ],
    "cors_checks": [
        {"name": "Wildcard Origin (ACAO: *)", "status": "fail", "severity": "high", "detail": "Access-Control-Allow-Origin is set to *, exposing the API to any origin.", "recommendation": "Replace * with a trusted origin."},
        {"name": "No Preflight Cache",        "status": "warn", "severity": "info", "detail": "Access-Control-Max-Age is not set.",                                        "recommendation": "Add Access-Control-Max-Age: 86400."},
    ],
}

# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────
def format_date(iso_str: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y  %I:%M:%S %p UTC")
    except Exception:
        return iso_str


def score_style(score: int, max_score: int) -> str:
    pct = (score / max_score * 100) if max_score else 0
    if pct >= 70:
        return "bold green"
    if pct >= 40:
        return "bold yellow"
    return "bold red"


def status_style(status: str) -> tuple[str, str]:
    if status == "pass":
        return "PASS", "bold green"
    if status == "fail":
        return "FAIL", "bold red"
    return "WARN", "bold yellow"


def severity_style(severity: str) -> str:
    return {"high": "red", "critical": "bold red", "medium": "yellow", "low": "cyan"}.get(severity, "white")


# ─────────────────────────────────────────────
#  Render results
# ─────────────────────────────────────────────
def render_results(data: dict) -> None:
    console.print()

    # ── Error state ──
    if data.get("error"):
        console.print(Panel(
            f"[bold red]Scan Error:[/bold red] {data['error']}",
            title="[red]MannAutomatedScanner[/red]",
            border_style="red",
        ))
        return

    # ── Summary row ──
    url        = data.get("url", "")
    status_code = data.get("status_code", "?")
    scanned_at  = format_date(data.get("scanned_at", ""))

    console.print(Rule("[bold cyan]MannAutomatedScanner Security Report[/bold cyan]"))
    console.print(f"  [bold cyan]URL[/bold cyan]     : {url}")
    console.print(f"  [bold cyan]Scanned[/bold cyan] : {scanned_at}  |  HTTP {status_code}")

    # ── Score ──
    score     = data.get("score", 0)
    max_score = data.get("max_score", 0)
    pct       = round(score / max_score * 100) if max_score else 0
    sty       = score_style(score, max_score)
    console.print(f"  [bold cyan]Score[/bold cyan]   : [{sty}]{score} / {max_score}  ({pct}%)[/{sty}]")
    console.print()

    # ── Secure Headers table ──
    h_table = Table(
        title="[bold]Secure Headers[/bold]",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white",
        show_lines=True,
        expand=False,
    )
    h_table.add_column("Header",       style="dim cyan",  no_wrap=True, min_width=32)
    h_table.add_column("Status",       justify="center",  no_wrap=True, width=8)
    h_table.add_column("Severity",     justify="center",  no_wrap=True, width=9)
    h_table.add_column("Value / Note", style="dim white", no_wrap=False)

    for chk in data.get("header_checks", []):
        label, lsty = status_style(chk["status"])
        sev_sty     = severity_style(chk["severity"])
        value_cell  = chk.get("value") or "[dim]-- missing[/dim]"
        h_table.add_row(
            chk["name"],
            f"[{lsty}]{label}[/{lsty}]",
            f"[{sev_sty}]{chk['severity'].upper()}[/{sev_sty}]",
            value_cell,
        )

    console.print(h_table)
    console.print()

    # ── CORS table ──
    c_table = Table(
        title="[bold]CORS Analysis[/bold]",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white",
        show_lines=True,
        expand=False,
    )
    c_table.add_column("Rule",     style="dim cyan", no_wrap=True, min_width=32)
    c_table.add_column("Status",   justify="center", no_wrap=True, width=8)
    c_table.add_column("Severity", justify="center", no_wrap=True, width=9)
    c_table.add_column("Detail",   style="dim white")

    for chk in data.get("cors_checks", []):
        label, lsty = status_style(chk["status"])
        sev_sty     = severity_style(chk.get("severity", "info"))
        c_table.add_row(
            chk["name"],
            f"[{lsty}]{label}[/{lsty}]",
            f"[{sev_sty}]{chk.get('severity', 'info').upper()}[/{sev_sty}]",
            chk.get("detail", ""),
        )

    console.print(c_table)
    console.print()

    # ── Recommendations panel ──
    recs = [
        c["recommendation"]
        for c in (data.get("header_checks", []) + data.get("cors_checks", []))
        if c.get("recommendation")
    ]
    if recs:
        rec_text = Text()
        for r in recs:
            rec_text.append("  > ", style="bold cyan")
            rec_text.append(r + "\n", style="white")
        console.print(Panel(
            rec_text,
            title=f"[bold cyan]Recommendations ({len(recs)})[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        ))
        console.print()

    console.print(Rule(style="bright_black"))


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def main() -> None:
    console.print(Panel(
        "[bold cyan]MannAutomatedScanner[/bold cyan]  --  Automated Web Security Scanner\n"
        "[dim]Audits a URL for secure headers & CORS misconfigurations[/dim]",
        border_style="cyan",
        padding=(0, 2),
    ))

    args = sys.argv[1:]

    # --demo flag: show demo data without hitting any URL
    if args and args[0] == "--demo":
        render_results(DEMO_RESULT)
        return

    # URL from CLI argument or interactive prompt
    if args:
        url = args[0].strip()
    else:
        url = Prompt.ask("\n  [cyan]Enter URL to scan[/cyan]", default="https://example.com")
        url = url.strip()

    if not url:
        console.print("[red]  URL must not be empty.[/red]")
        sys.exit(1)

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    console.print(f"\n  [dim]Scanning[/dim] [cyan]{url}[/cyan] [dim]...[/dim]\n")

    # ── Call the scanner core directly ──
    data = scan(url)
    render_results(data)


if __name__ == "__main__":
    main()
