#!/usr/bin/env python3
"""
MannAutomatedScanner - Automated Web Security Scanner (passive)
Audits a URL for missing/weak secure headers and CORS misconfigurations.

Usage:
    python MannPatel_AutomatedWebScanner.py <url>
    python MannPatel_AutomatedWebScanner.py https://example.com --json
    python MannPatel_AutomatedWebScanner.py https://example.com --browser-ua

Only scan sites you own or have written permission to test.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

TOOL_NAME = "MannAutomatedScanner"
TEST_ORIGIN = "https://evil.example"
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
WEIGHTS = {"high": 3, "medium": 2, "low": 1}

# Enable ANSI colours on Windows terminals
if os.name == "nt":
    os.system("")


# ─────────────────────────────────────────────
#  Header validators: return (status, note)
#  status: "pass" | "warn" | "fail"
# ─────────────────────────────────────────────
def check_csp(value: str, headers) -> tuple[str, str]:
    v = value.lower()
    problems = []
    if "unsafe-inline" in v:
        problems.append("allows 'unsafe-inline'")
    if "unsafe-eval" in v:
        problems.append("allows 'unsafe-eval'")
    if re.search(r"(default|script)-src[^;]*\s\*(\s|;|$)", v):
        problems.append("wildcard (*) source")
    if problems:
        return "warn", "CSP is weak: " + ", ".join(problems)
    return "pass", ""


def check_hsts(value: str, headers) -> tuple[str, str]:
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    if not m:
        return "fail", "HSTS has no valid max-age"
    age = int(m.group(1))
    if age == 0:
        return "fail", "HSTS max-age=0 disables HSTS"
    if age < 31536000:
        return "warn", f"HSTS max-age={age} is below recommended 31536000 (1 year)"
    return "pass", ""


def check_xfo(value: str, headers) -> tuple[str, str]:
    if value.strip().upper() in ("DENY", "SAMEORIGIN"):
        return "pass", ""
    return "warn", f"Unusual X-Frame-Options value: {value}"


def check_xcto(value: str, headers) -> tuple[str, str]:
    if value.strip().lower() == "nosniff":
        return "pass", ""
    return "warn", f"X-Content-Type-Options should be 'nosniff', got: {value}"


def check_referrer(value: str, headers) -> tuple[str, str]:
    if value.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        return "warn", f"Referrer-Policy '{value}' leaks full URLs"
    return "pass", ""


def check_any(value: str, headers) -> tuple[str, str]:
    return "pass", ""


SECURE_HEADERS = [
    {
        "name": "Content-Security-Policy", "severity": "high", "validator": check_csp,
        "recommendation": "Add a Content-Security-Policy header (avoid unsafe-inline/unsafe-eval and wildcards) to mitigate XSS.",
    },
    {
        "name": "Strict-Transport-Security", "severity": "high", "validator": check_hsts,
        "https_only": True,
        "recommendation": "Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    {
        "name": "X-Frame-Options", "severity": "medium", "validator": check_xfo,
        "accept_csp_frame_ancestors": True,
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN (or CSP frame-ancestors) to prevent clickjacking.",
    },
    {
        "name": "X-Content-Type-Options", "severity": "medium", "validator": check_xcto,
        "recommendation": "Add X-Content-Type-Options: nosniff to stop MIME-type sniffing.",
    },
    {
        "name": "Referrer-Policy", "severity": "low", "validator": check_referrer,
        "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin to control referrer leakage.",
    },
    {
        "name": "Permissions-Policy", "severity": "low", "validator": check_any,
        "recommendation": "Add a Permissions-Policy header to restrict browser APIs (camera, mic, geolocation).",
    },
]


def check_headers(headers, final_url: str) -> tuple[list[dict], float, float]:
    """Check secure headers. Returns (checks, score, max_score). Weighted by severity."""
    is_https = urlparse(final_url).scheme == "https"
    csp_value = headers.get("Content-Security-Policy", "")
    checks, score, max_score = [], 0.0, 0.0

    for rule in SECURE_HEADERS:
        name, sev = rule["name"], rule["severity"]
        weight = WEIGHTS[sev]

        if rule.get("https_only") and not is_https:
            checks.append({
                "name": name, "status": "skip", "value": None, "severity": sev,
                "detail": "Skipped: final URL is HTTP (HSTS only works over HTTPS).",
                "recommendation": "Serve the site over HTTPS and then enable HSTS.",
            })
            continue

        max_score += weight
        value = headers.get(name)  # requests headers are case-insensitive

        if value is None and rule.get("accept_csp_frame_ancestors") and "frame-ancestors" in csp_value.lower():
            score += weight
            checks.append({
                "name": name, "status": "pass", "value": "(covered by CSP frame-ancestors)",
                "severity": sev, "detail": "", "recommendation": "",
            })
            continue

        if value is None:
            checks.append({
                "name": name, "status": "fail", "value": None, "severity": sev,
                "detail": "Header is missing.", "recommendation": rule["recommendation"],
            })
            continue

        status, note = rule["validator"](value, headers)
        if status == "pass":
            score += weight
        elif status == "warn":
            score += weight / 2
        checks.append({
            "name": name, "status": status, "value": value, "severity": sev,
            "detail": note, "recommendation": rule["recommendation"] if status != "pass" else "",
        })
    return checks, score, max_score


def info_checks(headers) -> list[dict]:
    """Informational (not scored): Cache-Control and information disclosure headers."""
    out = []
    for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
        v = headers.get(h)
        if v:
            out.append({
                "name": f"Info disclosure: {h}", "status": "warn", "value": v, "severity": "low",
                "detail": f"{h} reveals technology/version: {v}",
                "recommendation": f"Hide or genericise the {h} header.",
            })
    if not headers.get("Cache-Control"):
        out.append({
            "name": "Cache-Control", "status": "info", "value": None, "severity": "info",
            "detail": "Cache-Control not set (informational, not scored).",
            "recommendation": "Set Cache-Control: no-store on sensitive/authenticated pages.",
        })
    return out


# ─────────────────────────────────────────────
#  CORS analysis
# ─────────────────────────────────────────────
def analyse_cors(get_headers, preflight_headers, test_origin: str = TEST_ORIGIN) -> list[dict]:
    issues = []

    def add(name, status, severity, detail, rec=""):
        issues.append({"name": name, "status": status, "severity": severity,
                       "detail": detail, "recommendation": rec})

    acao = get_headers.get("Access-Control-Allow-Origin", "")
    acac = get_headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    if acao == "*":
        add("Wildcard Origin (ACAO: *)", "fail", "high",
            "Access-Control-Allow-Origin is '*', exposing responses to any origin.",
            "Replace * with specific trusted origins (server-side allow-list).")
        if acac:
            add("Wildcard + Credentials", "fail", "critical",
                "Wildcard combined with Allow-Credentials: true (misconfiguration).",
                "Never combine ACAO: * with Access-Control-Allow-Credentials: true.")
    elif acao == test_origin:
        add("Arbitrary Origin Reflected", "fail", "critical" if acac else "high",
            f"Server reflected an untrusted Origin ({test_origin})"
            + (" AND allows credentials: any site can read authenticated responses." if acac
               else ", so any site can read responses."),
            "Validate Origin against a strict allow-list instead of echoing it back.")
    elif acao == "null":
        add("Null Origin Allowed", "fail", "high",
            "ACAO is 'null', which can be triggered from sandboxed iframes/local files.",
            "Do not allow the 'null' origin.")
    elif acao:
        add("Scoped ACAO", "pass", "info", f"ACAO restricted to: {acao}")
        if acac:
            add("Credentials Allowed", "warn", "medium",
                "Credentials are allowed; ensure the origin allow-list is tight.",
                "Confirm cross-origin credentials are really required.")
    else:
        add("No CORS Headers", "pass", "info",
            "No ACAO returned for a foreign Origin; cross-origin reads are blocked by default.")

    # Preflight (OPTIONS) results
    if preflight_headers is not None:
        p_acao = preflight_headers.get("Access-Control-Allow-Origin", "")
        methods = preflight_headers.get("Access-Control-Allow-Methods", "")
        dangerous = [m.strip() for m in methods.upper().split(",")
                     if m.strip() in ("PUT", "DELETE", "PATCH")]
        if p_acao in ("*", test_origin) and dangerous:
            add("Dangerous CORS Methods", "warn", "medium",
                f"Preflight allows state-changing methods for foreign origin: {', '.join(dangerous)}",
                "Remove methods that don't need to be cross-origin accessible.")
        if p_acao and not preflight_headers.get("Access-Control-Max-Age"):
            add("No Preflight Cache (Max-Age)", "info", "info",
                "Access-Control-Max-Age not set; browsers preflight every request.",
                "Add Access-Control-Max-Age: 86400.")
    return issues


# ─────────────────────────────────────────────
#  Main scanner
# ─────────────────────────────────────────────
def scan(url: str, timeout: int = 10, browser_ua: bool = False) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    ua = BROWSER_UA if browser_ua else f"{TOOL_NAME}/1.1"
    base_headers = {"User-Agent": ua}

    result = {
        "url": url,
        "final_url": None,
        "redirects": [],
        "scanned_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status_code": None,
        "headers_found": {},
        "header_checks": [],
        "info_checks": [],
        "cors_checks": [],
        "score": 0.0,
        "max_score": 0.0,
        "percent": 0,
        "grade": "-",
        "warnings": [],
        "error": None,
    }

    try:
        with requests.Session() as s:
            s.headers.update(base_headers)

            # 1) Normal request: used for security-header checks
            resp = s.get(url, timeout=timeout, allow_redirects=True)
            result["status_code"] = resp.status_code
            result["final_url"] = resp.url
            result["redirects"] = [r.url for r in resp.history]
            result["headers_found"] = dict(resp.headers)

            if resp.status_code in (401, 403, 429, 503):
                result["warnings"].append(
                    f"HTTP {resp.status_code}: the site (or a WAF/CDN) may be blocking the scanner, "
                    "so these headers may belong to a block page. Try --browser-ua or verify with curl -I."
                )
            if resp.history and urlparse(resp.url).netloc != urlparse(url).netloc:
                result["warnings"].append(
                    f"Redirected to a different host ({urlparse(resp.url).netloc}); results are for the final URL."
                )

            # 2) Header checks (weighted)
            checks, score, max_score = check_headers(resp.headers, resp.url)
            result["header_checks"] = checks
            result["info_checks"] = info_checks(resp.headers)
            result["score"] = score
            result["max_score"] = max_score
            pct = (score / max_score * 100) if max_score else 0
            result["percent"] = round(pct)
            result["grade"] = ("A" if pct >= 90 else "B" if pct >= 75 else
                               "C" if pct >= 55 else "D" if pct >= 35 else "F")

            # 3) CORS: GET with a foreign Origin + OPTIONS preflight
            cors_get = s.get(resp.url, timeout=timeout, allow_redirects=False,
                             headers={"Origin": TEST_ORIGIN})
            try:
                pre = s.options(resp.url, timeout=timeout, allow_redirects=False, headers={
                    "Origin": TEST_ORIGIN,
                    "Access-Control-Request-Method": "PUT",
                })
                pre_headers = pre.headers
            except requests.exceptions.RequestException:
                pre_headers = None
            result["cors_checks"] = analyse_cors(cors_get.headers, pre_headers)

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
def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def print_report(result: dict) -> None:
    RED, GREEN, YELL, CYAN, BOLD, GREY = "31", "32", "33", "36", "1", "90"
    icons = {"pass": ("✓", GREEN), "fail": ("✗", RED), "warn": ("⚠", YELL),
             "info": ("i", CYAN), "skip": ("-", GREY)}

    print()
    print(_c("═" * 64, BOLD))
    print(_c(f"  {TOOL_NAME} Security Report", BOLD))
    print(_c("═" * 64, BOLD))
    print(f"  URL     : {result['url']}")
    if result.get("final_url") and result["final_url"] != result["url"]:
        print(f"  Final   : {result['final_url']}")
    print(f"  Scanned : {result['scanned_at']}")
    if result.get("error"):
        print(_c(f"\n  ERROR: {result['error']}", RED))
        return
    print(f"  Status  : HTTP {result.get('status_code', '?')}")
    for w in result["warnings"]:
        print(_c(f"  ! {w}", YELL))
    print()

    print(_c("  [ Secure Headers ]", CYAN))
    for chk in result["header_checks"]:
        icon, col = icons[chk["status"]]
        val = (chk["value"] or "MISSING")[:50] if chk["status"] != "skip" else "SKIPPED"
        print(f"  {_c(icon, col)}  {chk['name']:<28} [{chk['severity']:<6}] {val}")
        if chk["detail"] and chk["status"] in ("warn", "fail", "skip"):
            print(_c(f"       {chk['detail']}", GREY))

    if result["info_checks"]:
        print()
        print(_c("  [ Informational (not scored) ]", CYAN))
        for chk in result["info_checks"]:
            icon, col = icons[chk["status"]]
            print(f"  {_c(icon, col)}  {chk['detail']}")

    print()
    print(_c("  [ CORS Analysis ]", CYAN))
    for chk in result["cors_checks"]:
        icon, col = icons[chk["status"]]
        print(f"  {_c(icon, col)}  {chk['name']}  [{chk['severity']}]")
        if chk["detail"]:
            print(_c(f"       {chk['detail']}", GREY))

    pct = result["percent"]
    col = GREEN if pct >= 70 else (YELL if pct >= 40 else RED)
    print()
    print(_c(f"  [ Score: {result['score']:.1f} / {result['max_score']:.0f} "
             f"({pct}%)  Grade: {result['grade']} ]", col))
    print(_c("  (weighted: high=3, medium=2, low=1; warnings earn half)", GREY))

    recs = []
    for c in result["header_checks"] + result["info_checks"] + result["cors_checks"]:
        if c.get("recommendation") and c["recommendation"] not in recs:
            recs.append(c["recommendation"])
    if recs:
        print()
        print(_c("  [ Recommendations ]", CYAN))
        for r in recs:
            print(f"  › {r}")
    print()
    print(_c("═" * 64, BOLD))


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="Passive web security header & CORS scanner.")
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--json", action="store_true", help="Print results as JSON")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--browser-ua", action="store_true",
                        help="Use a browser-like User-Agent (helps when a WAF blocks the scanner)")
    args = parser.parse_args()

    print("Note: scan only sites you own or have permission to test.", file=sys.stderr)
    data = scan(args.url, timeout=args.timeout, browser_ua=args.browser_ua)

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print_report(data)


if __name__ == "__main__":
    main()
