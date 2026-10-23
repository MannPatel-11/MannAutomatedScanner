#!/usr/bin/env python3
"""
MannAutomatedScanner — Automated Web Security Scanner
Audits a URL for missing/weak secure headers and CORS misconfigurations.

Usage:
    python scanner.py <url>
    python scanner.py https://example.com
"""

import sys
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone

# ─────────────────────────────────────────────
#  Header ruleset
# ─────────────────────────────────────────────
SECURE_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "recommendation": "Add a Content-Security-Policy header to restrict allowed content sources and mitigate XSS attacks.",
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "recommendation": "Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "recommendation": "Add X-Content-Type-Options: nosniff to stop MIME-type sniffing.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin to control referrer leakage.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "recommendation": "Add a Permissions-Policy header to restrict access to browser APIs (camera, mic, geolocation).",
    },
    "Cache-Control": {
        "severity": "low",
        "recommendation": "Set Cache-Control: no-store on sensitive endpoints to prevent caching of private data.",
    },
}

# ─────────────────────────────────────────────
#  CORS rules
# ─────────────────────────────────────────────
def analyse_cors(headers: dict) -> list[dict]:
    issues = []
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "").lower()
    acam = headers.get("Access-Control-Allow-Methods", "")
    acma = headers.get("Access-Control-Max-Age", "")

    if acao == "*":
        issues.append({
            "name": "Wildcard Origin (ACAO: *)",
            "status": "fail",
            "severity": "high",
            "detail": "Access-Control-Allow-Origin is set to wildcard (*), exposing the API to any origin.",
            "recommendation": "Replace * with a specific trusted origin or use server-side origin whitelisting.",
        })
    elif acao:
        # Validate it's a proper origin
        parsed = urlparse(acao)
        if parsed.scheme not in ("http", "https"):
            issues.append({
                "name": "Invalid ACAO Origin",
                "status": "warn",
                "severity": "medium",
                "detail": f"Access-Control-Allow-Origin value '{acao}' does not appear to be a valid origin.",
                "recommendation": "Ensure the value is a full origin like https://trusted.com",
            })
        else:
            issues.append({
                "name": "Scoped ACAO",
                "status": "pass",
                "severity": "info",
                "detail": f"Access-Control-Allow-Origin is restricted to: {acao}",
                "recommendation": "",
            })

    # Wildcard + credentials = critical
    if acao == "*" and acac == "true":
        issues.append({
            "name": "Wildcard + Credentials",
            "status": "fail",
            "severity": "critical",
            "detail": "CRITICAL: Wildcard origin combined with Allow-Credentials: true allows any site to make credentialed requests.",
            "recommendation": "Never combine ACAO: * with Access-Control-Allow-Credentials: true.",
        })
    elif acac == "true":
        issues.append({
            "name": "Credentials Allowed",
            "status": "warn",
            "severity": "medium",
            "detail": "Credentials are allowed. Ensure the origin is tightly scoped.",
            "recommendation": "Review whether credentials are truly needed cross-origin.",
        })

    # Dangerous methods
    dangerous = [m.strip() for m in acam.upper().split(",") if m.strip() in ("PUT", "DELETE", "PATCH")]
    if dangerous:
        issues.append({
            "name": "Dangerous CORS Methods",
            "status": "warn",
            "severity": "medium",
            "detail": f"Dangerous methods exposed via CORS: {', '.join(dangerous)}",
            "recommendation": "Remove methods that don't need to be cross-origin accessible.",
        })

    # Max-Age for preflight caching
    if acao and not acma:
        issues.append({
            "name": "No Preflight Cache (Max-Age)",
            "status": "warn",
            "severity": "info",
            "detail": "Access-Control-Max-Age is not set; browsers will send a preflight on every CORS request.",
            "recommendation": "Add Access-Control-Max-Age: 86400 to cache preflight results.",
        })

    if not acao:
        issues.append({
            "name": "No CORS Headers",
            "status": "pass",
            "severity": "info",
            "detail": "No CORS headers detected — cross-origin requests are blocked by default.",
            "recommendation": "",
        })

    return issues


# ─────────────────────────────────────────────
#  Main scanner
# ─────────────────────────────────────────────
def scan(url: str, timeout: int = 10) -> dict:
    """
    Scan a URL and return a structured results dict.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "url": url,
        "scanned_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "headers_found": {},
        "header_checks": [],
        "cors_checks": [],
        "score": 0,
        "max_score": 0,
        "error": None,
    }

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True,
                                headers={"User-Agent": "MannAutomatedScanner-Scanner/1.0"})
        resp_headers = {k.strip(): v.strip() for k, v in response.headers.items()}
        result["status_code"] = response.status_code
        result["headers_found"] = dict(resp_headers)

        # ── Secure header checks ──
        score = 0
        max_score = len(SECURE_HEADERS)
        for header, meta in SECURE_HEADERS.items():
            found = next((v for k, v in resp_headers.items() if k.lower() == header.lower()), None)
            if found:
                score += 1
                result["header_checks"].append({
                    "name": header,
                    "status": "pass",
                    "value": found,
                    "severity": meta["severity"],
                    "recommendation": "",
                })
            else:
                result["header_checks"].append({
                    "name": header,
                    "status": "fail",
                    "value": None,
                    "severity": meta["severity"],
                    "recommendation": meta["recommendation"],
                })

        # ── CORS checks ──
        result["cors_checks"] = analyse_cors(resp_headers)

        # ── Score ──
        result["score"] = score
        result["max_score"] = max_score

    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL Error: {e}"
    except requests.exceptions.ConnectionError:
        result["error"] = f"Could not connect to {url}"
    except requests.exceptions.Timeout:
        result["error"] = f"Request timed out after {timeout}s"
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────
#  CLI pretty-printer
# ─────────────────────────────────────────────
def _colour(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"

def print_report(result: dict) -> None:
    RED   = "31"
    GREEN = "32"
    YELL  = "33"
    CYAN  = "36"
    BOLD  = "1"

    print()
    print(_colour("═" * 60, BOLD))
    print(_colour(f"  MannAutomatedScanner Security Report", BOLD))
    print(_colour("═" * 60, BOLD))
    print(f"  URL    : {result['url']}")
    print(f"  Scanned: {result['scanned_at']}")
    if result.get("error"):
        print(_colour(f"\n  ERROR: {result['error']}", RED))
        return

    print(f"  Status : HTTP {result.get('status_code', '?')}")
    print()

    # Headers
    print(_colour("  [ Secure Headers ]", CYAN))
    for chk in result["header_checks"]:
        icon = "✓" if chk["status"] == "pass" else "✗"
        colour = GREEN if chk["status"] == "pass" else RED
        val = f"  {chk['value'][:60]}" if chk["value"] else "  MISSING"
        print(f"  {_colour(icon, colour)}  {chk['name']:<35}{val}")

    print()
    print(_colour("  [ CORS Analysis ]", CYAN))
    for chk in result["cors_checks"]:
        if chk["status"] == "pass":
            icon, colour = "✓", GREEN
        elif chk["status"] == "fail":
            icon, colour = "✗", RED
        else:
            icon, colour = "⚠", YELL
        print(f"  {_colour(icon, colour)}  {chk['name']}")
        if chk.get("detail"):
            print(f"       {_colour(chk['detail'], '90')}")

    # Score
    score = result["score"]
    max_s = result["max_score"]
    pct = (score / max_s * 100) if max_s else 0
    colour = GREEN if pct >= 70 else (YELL if pct >= 40 else RED)
    print()
    print(_colour(f"  [ Score: {score} / {max_s} — {pct:.0f}% ]", colour))
    print()

    # Recommendations
    recs = [c["recommendation"] for c in result["header_checks"] + result["cors_checks"]
            if c.get("recommendation")]
    if recs:
        print(_colour("  [ Recommendations ]", CYAN))
        for r in recs:
            print(f"  › {r}")
    print()
    print(_colour("═" * 60, BOLD))


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <url>")
        sys.exit(1)

    target = sys.argv[1]
    data = scan(target)
    print_report(data)
