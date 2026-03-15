"""
Entry point for KING — Bug Bounty Recon Platform CLI.
Usage: python -m cli.main [command]
"""
import typer
import asyncio
import json
import os
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.columns import Columns
from rich import box
from rich.style import Style
from typing import List, Optional

from app.core.input_layer import TargetIngestion, ScopeFilter
from app.core.recon_engine import ReconEngine
from app.core.crawler import Crawler
from app.core.js_engine import JSEngine
from app.core.secret_engine import SecretEngine
# Phase 2
from app.core.vuln.xss_engine import XSSEngine
from app.core.vuln.ssrf_engine import SSRFEngine
from app.core.vuln.bypass_403 import FourOhThreeBypass
from app.core.vuln.idor_engine import IDOREngine
from app.core.vuln.jwt_csrf_engine import JWTEngine, CSRFEngine
from app.core.vuln.cors_engine import CORSEngine
from app.core.vuln.business_logic import BusinessLogicEngine
from app.core.vuln.prototype_pollution import PrototypePollutionEngine
from app.core.vuln.ai_prompt_injection import AIPromptInjectionEngine
from app.core.vuln.mcp_security import MCPSecurityEngine
from app.core.data_search import DataSearchEngine
from app.core.screenshot_engine import ScreenshotEngine
from app.core.risk_engine import prioritize
from app.core.osint_engine import OSINTEngine
from app.core.ai_triage import AITriageEngine
from app.core.verbose import enable_verbose, v_section, v_info, v_finding

# ── Absolute default results directory (always inside the project) ─────────────
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUTPUT_DIR = os.path.join(_PROJECT_ROOT, "king_results")


# ── Module Registry ───────────────────────────────────────────────────────────
# Every module available in KING — used by `full-scan`
ALL_MODULES = [
    "subdomain", "osint", "crawler", "js", "secrets",
    "xss", "ssrf", "bypass_403", "idor", "jwt_csrf",
    "cors", "business_logic", "prototype_pollution",
    "ai_prompt_injection", "mcp_security", "data_search", "screenshots",
]

# Standard scan modules (fast, no screenshots/heavy modules)
STANDARD_MODULES = [
    "subdomain", "osint", "crawler", "js", "secrets",
    "xss", "ssrf", "bypass_403", "idor", "jwt_csrf",
]

app = typer.Typer(
    name="king",
    help="👑 KING — Elite Bug Bounty Recon Platform",
    add_completion=True,
)
console = Console()


# ══════════════════════════════════════════════════════════════════════════════
#  KING BANNER
# ══════════════════════════════════════════════════════════════════════════════

KING_ASCII = r"""
██╗  ██╗██╗███╗   ██╗ ██████╗
██║ ██╔╝██║████╗  ██║██╔════╝
█████╔╝ ██║██╔██╗ ██║██║  ███╗
██╔═██╗ ██║██║╚██╗██║██║   ██║
██║  ██╗██║██║ ╚████║╚██████╔╝
╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝
"""

CROWN = "           ♛ "

TAGLINES = [
    "Every target has a weakness. Find it first.",
    "Hunt. Exploit. Report. Repeat.",
    "Built for hunters who don't stop at the surface.",
    "The only scanner that thinks like an attacker.",
    "Subdomain? Found. Vulns? Owned. Report? Written.",
]


def print_king_banner():
    """Print the KING startup banner with crown and branding."""
    import random

    console.print()

    # Gradient-style ASCII art banner
    lines = KING_ASCII.strip("\n").split("\n")
    colors = ["bold gold1", "bold yellow", "bold yellow1", "bold dark_orange", "bold orange3", "bold gold3"]
    for i, line in enumerate(lines):
        color = colors[i % len(colors)]
        console.print(Align.center(f"[{color}]{line}[/{color}]"))

    console.print()

    # Crown + subtitle
    console.print(Align.center("[bold gold1]♛  ♛  ♛  ♛  ♛  ♛  ♛  ♛  ♛  ♛  ♛[/bold gold1]"))
    console.print()
    console.print(Align.center("[bold white]Elite Automated Bug Bounty Recon Platform[/bold white]"))
    console.print(Align.center(f"[dim italic]{random.choice(TAGLINES)}[/dim italic]"))
    console.print()
    console.print(Align.center("[bold gold1]♛  ♛  ♛  ♛  ♛  ♛  ♛  ♛  ♛  ♛  ♛[/bold gold1]"))
    console.print()

    # Info bar
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    info_line = (
        f"[dim]Version:[/dim] [bold cyan]1.0.0[/bold cyan]   "
        f"[dim]Platform:[/dim] [bold cyan]KING[/bold cyan]   "
        f"[dim]Time:[/dim] [bold cyan]{now}[/bold cyan]   "
        f"[dim]Author:[/dim] [bold cyan]@ankan[/bold cyan]"
    )
    console.print(Align.center(info_line))
    console.print(Rule(style="gold1"))
    console.print()


# ══════════════════════════════════════════════════════════════════════════════
#  STRUCTURED OUTPUT SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

def _make_scan_dir(base_dir: str, domain: str) -> str:
    """
    Create a timestamped, domain-specific scan directory:
    <base_dir>/
      └── getbeamer.com_20260315_204800/
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace("/", "_").replace(":", "_")
    scan_dir = os.path.join(base_dir, f"{safe_domain}_{ts}")
    os.makedirs(scan_dir, exist_ok=True)
    return scan_dir


def _ensure(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def _write_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def _write_txt(path: str, lines: List[str]):
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(l + "\n" for l in lines if l)


def save_structured_results(results: dict, scan_dir: str) -> dict:
    """
    Save all scan results into a clean folder hierarchy:

    <scan_dir>/
    ├── README.md                   — Human-readable summary
    ├── scan_meta.json              — Metadata (domain, time, module list)
    │
    ├── 01_subdomains/
    │   ├── all_hosts.txt           — Every subdomain found
    │   ├── alive.txt               — Only live hosts (HTTP 200/301/etc)
    │   ├── dead.txt                — Unreachable hosts
    │   ├── by_status/
    │   │   ├── 200.txt
    │   │   ├── 403.txt
    │   │   ├── 500.txt
    │   │   └── ...
    │   ├── by_source/
    │   │   ├── passive_subfinder.txt
    │   │   ├── passive_crt_sh.txt
    │   │   ├── active_bruteforce.txt
    │   │   └── ...
    │   └── full_data.json          — Complete enriched subdomain objects
    │
    ├── 02_assets/
    │   ├── all_urls.txt
    │   ├── js_files.txt
    │   ├── endpoints.txt           — API endpoints extracted from JS
    │   ├── interesting_paths.txt   — Admin, config, backup paths
    │   └── full_data.json
    │
    ├── 03_secrets/
    │   ├── all_secrets.json
    │   ├── high_confidence.json    — Confidence ≥ 0.8
    │   ├── api_keys.txt
    │   ├── tokens.txt
    │   └── by_type/                — One file per secret type
    │
    ├── 04_vulnerabilities/
    │   ├── all_findings.json
    │   ├── critical.json
    │   ├── high.json
    │   ├── medium.json
    │   ├── low.json
    │   ├── info.json
    │   └── by_type/
    │       ├── xss.json
    │       ├── ssrf.json
    │       ├── idor.json
    │       ├── bypass_403.json
    │       ├── jwt_csrf.json
    │       ├── cors.json
    │       ├── secrets.json
    │       └── ...
    │
    ├── 05_osint/
    │   ├── github_leaks.json
    │   ├── emails.json
    │   └── shodan_censys.json
    │
    └── 06_reports/
        ├── summary_report.md       — Full human-readable report
        ├── executive_summary.md    — Short 1-pager for management
        └── findings_poc.md         — Technical proof-of-concept notes
    """
    domain = results.get("domain", "unknown")
    scan_ts = datetime.now().isoformat()
    saved_files = []

    # ── scan_meta.json ──────────────────────────────────────────────────
    meta = {
        "tool": "KING — Bug Bounty Recon Platform",
        "version": "1.0.0",
        "domain": domain,
        "scan_timestamp": scan_ts,
        "scan_directory": scan_dir,
        "modules_run": results.get("modules_run", []),
        "total_subdomains": len(results.get("subdomains", [])),
        "live_subdomains": len([s for s in results.get("subdomains", []) if s.get("is_alive")]),
        "total_assets": len(results.get("assets", [])),
        "total_findings": len(results.get("findings", [])),
        "critical_count": len([f for f in results.get("findings",[]) if f.get("severity","").lower()=="critical"]),
        "high_count": len([f for f in results.get("findings",[]) if f.get("severity","").lower()=="high"]),
    }
    _write_json(os.path.join(scan_dir, "scan_meta.json"), meta)
    saved_files.append("scan_meta.json")

    # ── 01_subdomains/ ──────────────────────────────────────────────────
    sub_dir = _ensure(os.path.join(scan_dir, "01_subdomains"))
    subdomains = results.get("subdomains", [])
    alive = [s for s in subdomains if s.get("is_alive")]
    dead  = [s for s in subdomains if not s.get("is_alive")]

    _write_txt(os.path.join(sub_dir, "all_hosts.txt"),  [s.get("fqdn","") for s in subdomains])
    _write_txt(os.path.join(sub_dir, "alive.txt"),      [s.get("fqdn","") for s in alive])
    _write_txt(os.path.join(sub_dir, "dead.txt"),       [s.get("fqdn","") for s in dead])
    _write_json(os.path.join(sub_dir, "full_data.json"), subdomains)

    # by_status/
    status_dir = _ensure(os.path.join(sub_dir, "by_status"))
    from collections import defaultdict
    by_status = defaultdict(list)
    for s in alive:
        code = str(s.get("status_code", "unknown"))
        by_status[code].append(s.get("fqdn", ""))
    for code, hosts in by_status.items():
        _write_txt(os.path.join(status_dir, f"{code}.txt"), hosts)

    # by_source/
    source_dir = _ensure(os.path.join(sub_dir, "by_source"))
    by_source = defaultdict(list)
    for s in subdomains:
        for src in s.get("sources", []):
            safe_src = src.replace(":", "_").replace("/", "_")
            by_source[safe_src].append(s.get("fqdn", ""))
    for src, hosts in by_source.items():
        _write_txt(os.path.join(source_dir, f"{src}.txt"), hosts)

    saved_files.append("01_subdomains/")

    # ── 02_assets/ ──────────────────────────────────────────────────────
    assets_dir = _ensure(os.path.join(scan_dir, "02_assets"))
    assets = results.get("assets", [])

    _write_json(os.path.join(assets_dir, "full_data.json"), assets)
    _write_txt(os.path.join(assets_dir, "all_urls.txt"), [a.get("url","") for a in assets])

    js_files   = [a.get("url","") for a in assets if a.get("type") == "js"]
    _write_txt(os.path.join(assets_dir, "js_files.txt"), js_files)

    # endpoints from JS analysis
    js_findings = results.get("js_findings", [])
    all_endpoints = []
    for jf in js_findings:
        all_endpoints.extend(jf.get("endpoints", []))
    _write_txt(os.path.join(assets_dir, "endpoints.txt"), all_endpoints)

    # interesting paths
    interesting_kw = ["admin", "api", "config", ".env", "backup", "swagger", "debug", "panel", "dashboard"]
    interesting = [a.get("url","") for a in assets if any(kw in a.get("url","").lower() for kw in interesting_kw)]
    _write_txt(os.path.join(assets_dir, "interesting_paths.txt"), interesting)

    saved_files.append("02_assets/")

    # ── 03_secrets/ ─────────────────────────────────────────────────────
    secrets_dir = _ensure(os.path.join(scan_dir, "03_secrets"))
    all_findings = results.get("findings", [])
    secret_kw = ["secret", "key", "token", "credential", "password", "webhook", "api_key"]
    secret_findings = [f for f in all_findings if any(k in f.get("type","").lower() for k in secret_kw)]

    # Also pull from js_findings
    all_js_secrets = []
    for jf in js_findings:
        all_js_secrets.extend(jf.get("secrets", []))
    secret_findings_extended = secret_findings + all_js_secrets

    _write_json(os.path.join(secrets_dir, "all_secrets.json"), secret_findings_extended)

    high_conf = [s for s in secret_findings_extended if s.get("confidence", 0) >= 0.8]
    _write_json(os.path.join(secrets_dir, "high_confidence.json"), high_conf)

    # by_type/ for secrets
    stype_dir = _ensure(os.path.join(secrets_dir, "by_type"))
    from collections import defaultdict as dd2
    by_stype = dd2(list)
    for s in secret_findings_extended:
        stype = s.get("secret_type", s.get("type", "other")).lower().replace(" ", "_")
        by_stype[stype].append(s)
    for stype, items in by_stype.items():
        _write_json(os.path.join(stype_dir, f"{stype}.json"), items)

    # plain-text key lists
    _write_txt(os.path.join(secrets_dir, "api_keys.txt"),
        [s.get("value", s.get("secret", "")) for s in secret_findings_extended if "api" in s.get("secret_type","").lower()])
    _write_txt(os.path.join(secrets_dir, "tokens.txt"),
        [s.get("value", s.get("secret", "")) for s in secret_findings_extended if "token" in s.get("secret_type","").lower()])

    saved_files.append("03_secrets/")

    # ── 04_vulnerabilities/ ─────────────────────────────────────────────
    vuln_dir = _ensure(os.path.join(scan_dir, "04_vulnerabilities"))
    vuln_findings = [f for f in all_findings if f not in secret_findings]
    all_vulns = vuln_findings  # use all findings for severity split

    _write_json(os.path.join(vuln_dir, "all_findings.json"), all_findings)

    # by severity
    for sev in ["critical", "high", "medium", "low", "info"]:
        sev_list = [f for f in all_findings if f.get("severity","").lower() == sev]
        if sev_list:
            _write_json(os.path.join(vuln_dir, f"{sev}.json"), sev_list)

    # by type
    type_dir = _ensure(os.path.join(vuln_dir, "by_type"))
    TYPE_MAP = {
        "xss":        lambda f: "xss" in f.get("type","").lower(),
        "ssrf":       lambda f: "ssrf" in f.get("type","").lower(),
        "idor":       lambda f: "idor" in f.get("type","").lower() or "bola" in f.get("type","").lower(),
        "bypass_403": lambda f: "bypass" in f.get("type","").lower() or "403" in f.get("type",""),
        "cors":       lambda f: "cors" in f.get("type","").lower(),
        "jwt_csrf":   lambda f: any(x in f.get("type","").lower() for x in ["jwt","csrf"]),
        "prototype_pollution": lambda f: "proto" in f.get("type","").lower(),
        "business_logic": lambda f: any(x in f.get("type","").lower() for x in ["race","coupon","workflow","rate limit","privilege"]),
        "ai_llm":     lambda f: any(x in f.get("type","").lower() for x in ["ai prompt","llm","mcp"]),
        "secrets":    lambda f: any(k in f.get("type","").lower() for k in secret_kw),
        "cloud":      lambda f: any(x in f.get("type","").lower() for x in ["bucket","s3","cloud"]),
    }
    for category, fn in TYPE_MAP.items():
        cat_list = [f for f in all_findings if fn(f)]
        if cat_list:
            _write_json(os.path.join(type_dir, f"{category}.json"), cat_list)

    saved_files.append("04_vulnerabilities/")

    # ── 05_osint/ ───────────────────────────────────────────────────────
    osint_dir = _ensure(os.path.join(scan_dir, "05_osint"))
    osint_data = results.get("osint", {})

    gh_leaks = osint_data.get("github_leaks", [])
    emails   = [f for f in all_findings if f.get("type","").lower() in ["employee email","email format pattern"]]
    shodan   = osint_data.get("shodan", [])

    _write_json(os.path.join(osint_dir, "github_leaks.json"), gh_leaks)
    _write_json(os.path.join(osint_dir, "emails.json"), emails)
    _write_json(os.path.join(osint_dir, "shodan_censys.json"), shodan)
    saved_files.append("05_osint/")

    # ── 06_reports/ ─────────────────────────────────────────────────────
    report_dir = _ensure(os.path.join(scan_dir, "06_reports"))
    _write_markdown_report(results, os.path.join(report_dir, "summary_report.md"), full=True)
    _write_markdown_report(results, os.path.join(report_dir, "executive_summary.md"), full=False)
    _write_poc_notes(all_findings, os.path.join(report_dir, "findings_poc.md"))
    saved_files.append("06_reports/")

    # ── README.md ───────────────────────────────────────────────────────
    readme = f"""# KING Scan — {domain}
**Scan Time**: {scan_ts}
**Tool**: KING Bug Bounty Recon Platform v1.0.0

## Quick Stats
| Metric | Count |
|--------|-------|
| Total Subdomains | {meta['total_subdomains']} |
| Live Hosts | {meta['live_subdomains']} |
| Assets Found | {meta['total_assets']} |
| Total Findings | {meta['total_findings']} |
| Critical | {meta['critical_count']} |
| High | {meta['high_count']} |

## Directory Structure
| Folder | Contents |
|--------|----------|
| `01_subdomains/` | All hosts, live/dead split, by source and status code |
| `02_assets/` | URLs, JS files, extracted endpoints, interesting paths |
| `03_secrets/` | API keys, tokens, high-confidence secrets by type |
| `04_vulnerabilities/` | Findings split by severity and vulnerability class |
| `05_osint/` | GitHub leaks, employee emails, Shodan/Censys data |
| `06_reports/` | Markdown reports: summary, executive, PoC notes |

## Quick Navigation
- 🔴 **Critical/High vulns** → `04_vulnerabilities/critical.json`, `04_vulnerabilities/high.json`
- 🔑 **Secrets** → `03_secrets/high_confidence.json`
- 🌐 **Live hosts** → `01_subdomains/alive.txt`
- 📜 **Full report** → `06_reports/summary_report.md`
"""
    with open(os.path.join(scan_dir, "README.md"), "w") as f:
        f.write(readme)

    return {"scan_dir": scan_dir, "files_created": saved_files, "meta": meta}


# ── Markdown Report Writers ───────────────────────────────────────────────────

def _write_markdown_report(results: dict, path: str, full: bool = True):
    domain    = results.get("domain", "")
    subdom    = results.get("subdomains", [])
    findings  = results.get("findings", [])
    alive     = [s for s in subdom if s.get("is_alive")]

    crits  = [f for f in findings if f.get("severity","").lower() == "critical"]
    highs  = [f for f in findings if f.get("severity","").lower() == "high"]

    lines = [
        f"# {'KING Recon Report' if full else 'Executive Summary'}: {domain}\n\n",
        f"> Generated by **KING Bug Bounty Recon Platform v1.0** — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n",
        f"## 📊 Summary\n",
        f"| Metric | Value |\n|--------|-------|\n",
        f"| Target Domain | `{domain}` |\n",
        f"| Live Hosts | {len(alive)} / {len(subdom)} |\n",
        f"| Total Findings | {len(findings)} |\n",
        f"| Critical | 🔴 {len(crits)} |\n",
        f"| High | 🟠 {len(highs)} |\n\n",
    ]

    if full:
        lines += [f"## 🌐 Live Subdomains ({len(alive)})\n\n"]
        for s in alive:
            cdn = f" [{s.get('cdn_name','')}]" if s.get("cdn_name") else ""
            lines.append(f"- `{s['fqdn']}` — HTTP {s.get('status_code','')} — {s.get('title','') or 'No title'}{cdn}\n")
        lines.append("\n")

    lines += [f"## 🔍 Findings ({len(findings)} total)\n\n"]
    for f in findings:
        sev = f.get("severity","info").upper()
        score = f.get("risk_score","")
        lines += [
            f"### [{sev}] {f.get('type','')}" + (f" — Score: {score}/10" if score else "") + "\n",
            f"- **URL**: `{f.get('url','N/A')}`\n",
            f"- **Evidence**: {f.get('evidence','')}\n",
            f"- **Next Step**: {f.get('suggested_next_step','')}\n\n",
        ]
        if not full and len(lines) > 80:
            lines.append("*...truncated. See full report for all findings.*\n")
            break

    with open(path, "w", encoding="utf-8") as file:
        file.writelines(lines)


def _write_poc_notes(findings: List[dict], path: str):
    lines = ["# Findings — Proof-of-Concept Notes\n\n"]
    actionable = [f for f in findings if f.get("severity","").lower() in ["critical","high","medium"]]
    if not actionable:
        lines.append("_No actionable findings at medium severity or above._\n")
    for i, f in enumerate(actionable, 1):
        lines += [
            f"## {i}. {f.get('type','')}\n",
            f"**Severity**: `{f.get('severity','').upper()}` | **Confidence**: `{f.get('confidence','')}` | **Score**: `{f.get('risk_score','N/A')}/10`\n\n",
            f"**Target**: `{f.get('url','N/A')}`\n\n",
            f"**Evidence**:\n```\n{f.get('evidence','')}\n```\n\n",
        ]
        if f.get("payload"):
            lines.append(f"**Payload**:\n```\n{f.get('payload','')}\n```\n\n")
        if f.get("ai_report"):
            lines.append(f"**AI Analysis**:\n{f.get('ai_report','')}\n\n")
        lines.append(f"> **Next Step**: {f.get('suggested_next_step','')}\n\n---\n\n")

    with open(path, "w", encoding="utf-8") as file:
        file.writelines(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  SCAN COMMAND
# ══════════════════════════════════════════════════════════════════════════════

@app.command(name="scan")
def scan(
    domain: Optional[str] = typer.Argument(None, help="Target domain (e.g. example.com)"),
    targets: Optional[str] = typer.Option(None, "--targets", "-T", help="File containing list of target domains (one per line)"),
    in_scope: Optional[List[str]] = typer.Option(None, "--scope", "-s", help="In-scope rules"),
    out_of_scope: Optional[List[str]] = typer.Option(None, "--exclude", "-e", help="Out-of-scope rules"),
    modules: Optional[List[str]] = typer.Option(
        ["subdomain", "osint", "crawler", "js", "secrets", "xss", "ssrf", "bypass_403", "idor", "jwt_csrf"],
        "--module", "-m", help="Modules to run"
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Single output file (.json or .md)"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-d", help="Root directory for structured results (default: <project>/king_results)"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Custom wordlist for directory/endpoint discovery (ffuf, feroxbuster, internal)"),
    passive: bool = typer.Option(False, "--passive", help="Passive mode only"),
    threads: int = typer.Option(30, "--threads", "-t", help="Thread count"),
    blind_xss: Optional[str] = typer.Option(None, "--blind-xss", help="Blind XSS callback URL"),
    oob_server: Optional[str] = typer.Option(None, "--oob", help="OOB callback server for SSRF"),
    ai_report: bool = typer.Option(False, "--ai-report", help="Generate AI-powered reports for high findings"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose mode: stream every discovered item live"),
):
    """
    👑 Run a full recon scan + vulnerability analysis against a target domain.

    Results are automatically saved in a structured directory under --output-dir.

    \\b
    Examples:
        king scan example.com
        king scan --targets domains.txt
        king scan example.com -m subdomain -m xss --blind-xss https://cb.example.net
        king scan example.com --passive --output-dir ./results
        king scan example.com --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
        king scan example.com --ai-report -v
    """
    print_king_banner()

    # ── Resolve targets ──────────────────────────────────────────────────
    targets_list = []
    if domain:
        targets_list.append(domain)
    if targets:
        targets_path = os.path.abspath(targets)
        if not os.path.exists(targets_path):
            console.print(f"  [bold red]⚠[/bold red] Targets file not found: [dim]{targets_path}[/dim]")
            raise typer.Exit(code=1)
        with open(targets_path) as f:
            targets_list.extend([line.strip() for line in f if line.strip()])

    if not targets_list:
        console.print("  [bold red]⚠[/bold red] No target domain or targets file provided.")
        console.print("  Use: [cyan]king scan <domain>[/cyan] OR [cyan]king scan --targets <file>[/cyan]")
        raise typer.Exit(code=1)

    # ── Resolve output directory (always absolute) ────────────────────────
    resolved_output_dir = os.path.abspath(output_dir) if output_dir else DEFAULT_OUTPUT_DIR
    os.makedirs(resolved_output_dir, exist_ok=True)

    # Show results path BEFORE anything else so user always knows where to find it
    console.print(
        f"  [bold white]📁 Results will be saved to:[/bold white] "
        f"[bold cyan]{resolved_output_dir}/<scan_folder>/[/bold cyan]"
    )
    console.print()

    if verbose:
        enable_verbose()
        console.print(Panel(
            "[bold yellow]VERBOSE MODE ON[/bold yellow] — Every discovered subdomain, URL, probe and\n"
            "finding will stream to your terminal in real-time.\n"
            "Format:  [green][+][/green] found  [dim][~][/dim] info  [bold red][!][/bold red] finding  [magenta][>][/magenta] tool  [dim]→[/dim] probe\n\n"
            "[bold white]🔧 Tool Stack:[/bold white]\n"
            "  Subdomains : subfinder · amass · crt.sh · theHarvester · gau · waybackurls\n"
            "  Endpoints  : katana · gospider · ffuf · feroxbuster · internal-crawler\n"
            "  Secrets    : trufflehog · gitleaks · regex-engine\n"
            "  XSS        : dalfox · XSStrike · kxss · internal-engine\n"
            "  403 Bypass : byp4xx · 4-Zero-3 · internal-engine",
            title="[bold yellow]♛ KING — Verbose Mode[/bold yellow]",
            border_style="yellow",
            padding=(0, 2),
        ))
        console.print()

    if wordlist:
        wordlist_abs = os.path.abspath(wordlist)
        if not os.path.exists(wordlist_abs):
            console.print(f"  [bold red]⚠[/bold red] Custom wordlist not found: [dim]{wordlist_abs}[/dim] — using default")
            wordlist_abs = None
        else:
            console.print(f"  [bold white]📖 Custom wordlist:[/bold white] [cyan]{wordlist_abs}[/cyan] ([dim]{sum(1 for _ in open(wordlist_abs))} words[/dim])")
            console.print()
    else:
        wordlist_abs = None

    # ── Iterate through targets ──────────────────────────────────────────
    for current_domain in targets_list:
        console.rule(f"[bold gold1]♛ Scanning Target: {current_domain}[/bold gold1]", style="gold1")
        console.print()

        # Create unique timestamped folder for this specific target
        current_scan_dir = _make_scan_dir(resolved_output_dir, current_domain)
        console.print(f"  [bold white]📁 Target Results Folder:[/bold white] [bold cyan]{current_scan_dir}[/bold cyan]")
        console.print()

        scope_rules = in_scope or [f"*.{current_domain}", current_domain]
        scope = ScopeFilter(in_scope=scope_rules, out_of_scope=out_of_scope or [])
        results = {
            "domain": current_domain,
            "findings": [],
            "subdomains": [],
            "assets": [],
            "modules_run": list(modules),
        }

        # Target panel (for the current domain)
        wl_str = os.path.basename(wordlist_abs) if wordlist_abs else "default"
        console.print(Panel(
            f"[bold white]🎯 Target[/bold white]: [bold cyan]{current_domain}[/bold cyan]\n"
            f"[bold white]📦 Modules[/bold white]: [yellow]{', '.join(modules)}[/yellow]\n"
            f"[bold white]⚙️  Threads[/bold white]: [green]{threads}[/green]  "
            f"[bold white]Mode[/bold white]: [{'dim' if passive else 'bold red'}]{'PASSIVE' if passive else 'ACTIVE'}[/{'dim' if passive else 'bold red'}]\n"
            f"[bold white]📖 Wordlist[/bold white]: [dim]{wl_str}[/dim]",
            title="[bold gold1]♛ KING — Scan Configuration[/bold gold1]",
            border_style="gold1",
            padding=(1, 2),
        ))
        console.print()

        scan_start = time.time()

        async def run():
            recon = ReconEngine(domain=current_domain, scope=scope, threads=threads)
            crawler = Crawler(scope=scope, threads=threads, custom_wordlist=wordlist_abs)
            js_engine = JSEngine()
            secret_engine = SecretEngine()
            osint = OSINTEngine()
            ai = AITriageEngine()

            all_findings = []
            subdomains, assets, js_findings = [], [], []

            # ── Phase 1: Recon ───────────────────────────────────────────────
            _phase_header("Phase 1", "Reconnaissance & Asset Discovery", "🔍")

            if "subdomain" in modules:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                              TimeElapsedColumn(), console=console, transient=True) as p:
                    p.add_task(f"[cyan]Enumerating subdomains for {current_domain}...", total=None)
                    recon_results = await recon.enumerate(passive_only=passive)

                subdomains = recon_results.get("subdomains", [])
                results["subdomains"] = subdomains

                if passive:
                    assets = recon_results.get("assets", [])
                    results["assets"] = assets

                _print_subdomains(subdomains)

            if "osint" in modules and subdomains:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                              TimeElapsedColumn(), console=console, transient=True) as p:
                    p.add_task("[cyan]Running OSINT...", total=None)
                    osint_data = await osint.scan(current_domain, subdomains)
                results["osint"] = osint_data
                gh_count = len(osint_data.get("github_leaks", []))
                _status_line("OSINT", f"{gh_count} GitHub leaks" if gh_count else "No leaks", bool(gh_count))
                if gh_count:
                    all_findings.extend(osint_data.get("github_leaks", []))

            if "crawler" in modules and subdomains and not passive:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                              TimeElapsedColumn(), console=console, transient=True) as p:
                    p.add_task("[cyan]Crawling + directory brute-forcing...", total=None)
                    assets = await crawler.crawl_all(subdomains)
                results["assets"] = assets
                _status_line("Crawler", f"{len(assets)} assets discovered", bool(assets))

            if "js" in modules:
                js_assets = [a for a in assets if a.get("type") == "js"]
                if js_assets:
                    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                                  TimeElapsedColumn(), console=console, transient=True) as p:
                        p.add_task(f"[cyan]Analyzing {len(js_assets)} JS files...", total=None)
                        js_findings = await js_engine.analyze_all(js_assets)
                    results["js_findings"] = js_findings
                    ep_count = sum(len(j.get("endpoints", [])) for j in js_findings)
                    _status_line("JS Engine", f"{ep_count} endpoints extracted", bool(ep_count))
                    _print_js_findings(js_findings)

            if "secrets" in modules:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                              TimeElapsedColumn(), console=console, transient=True) as p:
                    p.add_task("[cyan]Scanning for secrets...", total=None)
                    secrets = await secret_engine.scan_all(assets)
                all_findings.extend(secrets)
                _status_line("Secrets", f"{len(secrets)} secrets found", bool(secrets))

            # ── Phase 2: Vuln Scanning ───────────────────────────────────────
            if not passive:
                _phase_header("Phase 2", "Vulnerability Analysis", "💀")
                vuln_findings = await _run_vuln_engines(
                    modules=list(modules),
                    assets=assets,
                    js_findings=js_findings,
                    domain=current_domain,
                    blind_xss=blind_xss,
                    oob_server=oob_server,
                )
                all_findings.extend(vuln_findings)
            else:
                console.print("[dim]⏩ Phase 2 skipped (passive mode)[/dim]\n")

            # ── Risk Scoring ───────────────────────────────────────────────
            prioritized = prioritize(all_findings)
            results["findings"] = prioritized

            if ai_report and prioritized:
                top = [f for f in prioritized if f.get("risk_score", 0) >= 6.0][:20]
                results["triaged_findings"] = ai.triage_findings(top)

            return results

        final = asyncio.run(run())

        elapsed = time.time() - scan_start
        _phase_header("Phase 3", "Saving Structured Results", "💾")

        # Save to the unique per-target scan directory
        scan_info = save_structured_results(final, current_scan_dir)
        scan_dir  = scan_info["scan_dir"]

        # Optional single-file output
        if output:
            if output.endswith(".json"):
                _write_json(output, final)
            elif output.endswith(".md"):
                _write_markdown_report(final, output, full=True)
            _status_line("Output File", output, True)

        # Results summary panel
        meta = scan_info["meta"]
        crits = meta["critical_count"]
        highs = meta["high_count"]
        total = meta["total_findings"]

        _print_findings(final.get("findings", []))

        console.print()
        console.print(Panel(
            f"[bold white]📁 Scan Directory[/bold white]: [bold cyan]{scan_dir}[/bold cyan]\n\n"
            f"[bold white]🌐 Subdomains[/bold white]:  {meta['live_subdomains']} alive / {meta['total_subdomains']} total\n"
            f"[bold white]📦 Assets[/bold white]:       {meta['total_assets']}\n"
            f"[bold white]🔍 Findings[/bold white]:     {total} total  "
            f"[red]🔴 {crits} Critical[/red]  [orange3]🟠 {highs} High[/orange3]\n\n"
            f"[bold white]⏱  Duration[/bold white]:     {elapsed:.1f}s\n\n"
            f"[dim]Quick access:[/dim]\n"
            f"  [cyan]cat {scan_dir}/01_subdomains/alive.txt[/cyan]\n"
            f"  [cyan]cat {scan_dir}/04_vulnerabilities/critical.json[/cyan]\n"
            f"  [cyan]open {scan_dir}/06_reports/summary_report.md[/cyan]",
            title=f"[bold gold1]♛ KING — Scan Complete: {current_domain}[/bold gold1]",
            border_style="gold1",
            padding=(1, 2),
        ))
        console.print()


# ══════════════════════════════════════════════════════════════════════════════
#  PRINT HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _phase_header(phase: str, title: str, emoji: str):
    console.print(Rule(
        f"[bold gold1]{emoji}  {phase}: {title}[/bold gold1]",
        style="gold1",
    ))
    console.print()


def _status_line(module: str, message: str, is_hit: bool):
    icon  = "[bold red]⚠ [/bold red]" if is_hit else "[green]✔ [/green]"
    color = "bold red" if is_hit else "green"
    console.print(f"  {icon}[bold]{module}[/bold]: [{color}]{message}[/{color}]")


def _print_subdomains(subdomains: List[dict]):
    alive = [s for s in subdomains if s.get("is_alive")]
    if not alive:
        console.print("  [dim]No live subdomains found.[/dim]\n")
        return
    table = Table(
        title=f"🌐 Live Subdomains — {len(alive)}/{len(subdomains)}",
        show_lines=False,
        box=box.SIMPLE_HEAD,
        border_style="cyan",
        title_style="bold cyan",
    )
    table.add_column("FQDN",   style="bold cyan", min_width=30)
    table.add_column("Status", style="green",   min_width=6)
    table.add_column("Title",  style="dim",     max_width=35)
    table.add_column("CDN",    style="yellow",  min_width=10)
    table.add_column("WAF",    style="red",     min_width=10)
    table.add_column("Server", style="dim",     min_width=10)
    for s in alive[:60]:
        status = str(s.get("status_code", ""))
        status_color = "green" if status.startswith("2") else "yellow" if status.startswith("3") else "red"
        table.add_row(
            s.get("fqdn", ""),
            f"[{status_color}]{status}[/{status_color}]",
            (s.get("title") or "")[:35],
            s.get("cdn_name") or "",
            s.get("waf_detected") or "",
            (s.get("server") or "")[:12],
        )
    console.print(table)
    console.print()


def _print_findings(findings: List[dict]):
    if not findings:
        console.print("  [dim]No findings to display.[/dim]")
        return
    table = Table(
        title=f"🎯 Findings — Top {min(len(findings),30)} by Risk Score",
        show_lines=True,
        box=box.SIMPLE_HEAD,
        border_style="red",
        title_style="bold red",
    )
    table.add_column("Score",    style="bold red",    min_width=6)
    table.add_column("Severity", style="bold",        min_width=9)
    table.add_column("Type",     style="yellow",      min_width=28, max_width=35)
    table.add_column("URL",      style="cyan",        max_width=50)
    table.add_column("Evidence", style="dim",         max_width=40)

    SEV_COLORS = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green", "INFO": "dim"}
    for f in findings[:30]:
        score = f"{f.get('risk_score', '')}"
        sev   = f.get("severity", "info").upper()
        table.add_row(
            score,
            Text(sev, style=SEV_COLORS.get(sev, "white")),
            f.get("type", "")[:35],
            f.get("url", "")[:50],
            (f.get("evidence") or f.get("why_it_matters") or "")[:40],
        )
    console.print(table)


def _print_js_findings(js_findings: List[dict]):
    if not js_findings:
        return
    table = Table(
        title=f"📜 JS Intelligence — {len(js_findings)} files",
        show_lines=False,
        box=box.SIMPLE_HEAD,
    )
    table.add_column("File",      style="cyan")
    table.add_column("Endpoints", style="green")
    table.add_column("Secrets",   style="red")
    for j in js_findings[:20]:
        table.add_row(
            j.get("url", "")[-50:],
            str(len(j.get("endpoints", []))),
            str(len(j.get("secrets", []))),
        )
    console.print(table)
    console.print()


# ══════════════════════════════════════════════════════════════════════════════
#  INFO COMMAND
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
#  CONCURRENT VULN ENGINE RUNNER
# ══════════════════════════════════════════════════════════════════════════════

async def _run_vuln_engines(
    modules: List[str],
    assets: List[dict],
    js_findings: List[dict],
    domain: str,
    blind_xss: Optional[str] = None,
    oob_server: Optional[str] = None,
) -> List[dict]:
    """
    Run all selected vuln engines CONCURRENTLY using asyncio.gather.
    This is what powers both `scan --full` and `full-scan`.
    """
    tasks = {}

    if "xss" in modules:
        tasks["XSS"] = XSSEngine(blind_xss_url=blind_xss).scan(assets, js_findings)
    if "ssrf" in modules:
        tasks["SSRF"] = SSRFEngine(oob_server=oob_server).scan(assets)
    if "bypass_403" in modules:
        tasks["403 Bypass"] = FourOhThreeBypass().scan(assets)
    if "idor" in modules:
        tasks["IDOR"] = IDOREngine().scan(assets)
    if "jwt_csrf" in modules:
        tasks["JWT/CSRF"] = CSRFEngine().scan(assets)
    if "cors" in modules:
        tasks["CORS"] = CORSEngine().scan(assets)
    if "business_logic" in modules:
        tasks["Business Logic"] = BusinessLogicEngine().scan(domain, assets)
    if "prototype_pollution" in modules:
        tasks["Prototype Pollution"] = PrototypePollutionEngine().scan(assets, js_findings)
    if "ai_prompt_injection" in modules:
        base_url = f"https://{domain}"
        tasks["AI Prompt Injection"] = AIPromptInjectionEngine().scan(base_url, assets)
    if "mcp_security" in modules:
        base_url = f"https://{domain}"
        tasks["MCP Security"] = MCPSecurityEngine().scan(base_url, assets)
    if "data_search" in modules:
        tasks["Data Search"] = DataSearchEngine().scan(domain)

    if not tasks:
        return []

    # Show concurrent launch message
    engine_names = list(tasks.keys())
    console.print(f"  [gold1]⚡ Launching {len(engine_names)} engines concurrently:[/gold1]")
    for name in engine_names:
        console.print(f"     [dim]→[/dim] [cyan]{name}[/cyan]")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as p:
        p.add_task(f"[cyan]Running {len(tasks)} vuln engines in parallel...", total=None)
        results_list = await asyncio.gather(*tasks.values(), return_exceptions=True)

    all_findings = []
    for name, result in zip(tasks.keys(), results_list):
        if isinstance(result, Exception):
            console.print(f"  [red]✗ {name}: {result}[/red]")
            continue
        count = len(result)
        _status_line(name, f"{count} findings" if count else "Clean", bool(count))
        all_findings.extend(result)

    return all_findings


# ══════════════════════════════════════════════════════════════════════════════
#  FULL-SCAN COMMAND  (fires EVERYTHING at once)
# ══════════════════════════════════════════════════════════════════════════════

@app.command(name="full-scan")
def full_scan(
    domain: str = typer.Argument(..., help="Target domain (e.g. example.com)"),
    in_scope: Optional[List[str]] = typer.Option(None, "--scope", "-s", help="In-scope rules"),
    out_of_scope: Optional[List[str]] = typer.Option(None, "--exclude", "-e", help="Out-of-scope rules"),
    output_dir: Optional[str] = typer.Option("./king_results", "--output-dir", "-d", help="Output directory"),
    threads: int = typer.Option(30, "--threads", "-t", help="Thread count"),
    blind_xss: Optional[str] = typer.Option(None, "--blind-xss", help="Blind XSS callback URL"),
    oob_server: Optional[str] = typer.Option(None, "--oob", help="OOB callback server"),
    ai_report: bool = typer.Option(False, "--ai-report", help="AI-powered report generation"),
    screenshots: bool = typer.Option(False, "--screenshots", help="Capture headless screenshots of all live hosts"),
    skip_active: bool = typer.Option(False, "--passive", help="Skip active enumeration"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose mode: stream every discovered item live"),
):
    """
    👑 FULL KING SCAN — Launch ALL 15+ recon & vuln engines simultaneously.

    \\b
    This fires EVERYTHING at once:
      Phase 1 (Sequential — each feeds into the next):
        subdomain → osint → crawler → js → secrets

      Phase 2 (CONCURRENT — all run in parallel):
        xss | ssrf | 403-bypass | idor | jwt/csrf | cors
        business-logic | prototype-pollution | ai-prompt-injection
        mcp-security | data-search

      Phase 3:
        screenshots (optional) → structured save → reports

    \\b
    Examples:
        king full-scan example.com
        king full-scan example.com --screenshots --ai-report
        king full-scan example.com --oob https://your.burp.server --blind-xss https://xss.ht
    """
    print_king_banner()

    if verbose:
        enable_verbose()
        console.print(Panel(
            "[bold yellow]VERBOSE MODE ON[/bold yellow] — Every subdomain, URL, probe and finding streams live.\n"
            "Format:  [green][+][/green] found  [dim][~][/dim] info  [bold red][!][/bold red] finding  [magenta][>][/magenta] tool  [dim]→[/dim] probe",
            title="[bold yellow]♛ KING — Verbose Mode[/bold yellow]",
            border_style="yellow",
            padding=(0, 2),
        ))
        console.print()


    scope_rules = in_scope or [f"*.{domain}", domain]
    scope = ScopeFilter(in_scope=scope_rules, out_of_scope=out_of_scope or [])
    modules = ALL_MODULES

    results = {
        "domain": domain,
        "findings": [],
        "subdomains": [],
        "assets": [],
        "modules_run": modules,
    }

    console.print(Panel(
        f"[bold white]🎯 Target[/bold white]  : [bold cyan]{domain}[/bold cyan]\n"
        f"[bold white]⚡ Mode[/bold white]    : [bold red]FULL KING SCAN — ALL {len(modules)} MODULES[/bold red]\n"
        f"[bold white]⚙️  Threads[/bold white] : [green]{threads}[/green]  "
        f"[bold white]Screenshots[/bold white]: [{'green' if screenshots else 'dim'}]{'ON' if screenshots else 'OFF'}[/{'green' if screenshots else 'dim'}]  "
        f"[bold white]AI Report[/bold white]  : [{'green' if ai_report else 'dim'}]{'ON' if ai_report else 'OFF'}[/{'green' if ai_report else 'dim'}]",
        title="[bold gold1]♛ KING — FULL SCAN MODE[/bold gold1]",
        border_style="bold red",
        padding=(1, 2),
    ))
    console.print()

    scan_start = time.time()

    async def run():
        recon        = ReconEngine(domain=domain, scope=scope, threads=threads)
        crawler_eng  = Crawler(scope=scope, threads=threads)
        js_engine    = JSEngine()
        secret_engine = SecretEngine()
        osint_eng    = OSINTEngine()
        ai           = AITriageEngine()

        all_findings = []
        subdomains, assets, js_findings = [], [], []

        # ── PHASE 1: SEQUENTIAL (each step builds on the previous) ───────
        _phase_header("Phase 1", "Reconnaissance & Asset Discovery", "🔍")

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      TimeElapsedColumn(), console=console, transient=True) as p:
            p.add_task("[cyan]Enumerating subdomains (all passive + active sources)...", total=None)
            recon_results = await recon.enumerate(passive_only=skip_active)

        subdomains = recon_results.get("subdomains", [])
        results["subdomains"] = subdomains
        _print_subdomains(subdomains)

        if subdomains:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          TimeElapsedColumn(), console=console, transient=True) as p:
                p.add_task("[cyan]OSINT — GitHub leaks, Shodan, email recon...", total=None)
                osint_data = await osint_eng.scan(domain, subdomains)
            results["osint"] = osint_data
            gh_count = len(osint_data.get("github_leaks", []))
            _status_line("OSINT", f"{gh_count} GitHub leaks" if gh_count else "No leaks", bool(gh_count))
            if gh_count:
                all_findings.extend(osint_data.get("github_leaks", []))

        if not skip_active and subdomains:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          TimeElapsedColumn(), console=console, transient=True) as p:
                p.add_task("[cyan]Crawling + directory brute-force...", total=None)
                assets = await crawler_eng.crawl_all(subdomains)
            results["assets"] = assets
            _status_line("Crawler", f"{len(assets)} assets", bool(assets))

        js_assets = [a for a in assets if a.get("type") == "js"]
        if js_assets:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          TimeElapsedColumn(), console=console, transient=True) as p:
                p.add_task(f"[cyan]JS Intelligence — {len(js_assets)} files...", total=None)
                js_findings = await js_engine.analyze_all(js_assets)
            results["js_findings"] = js_findings
            ep_count = sum(len(j.get("endpoints", [])) for j in js_findings)
            _status_line("JS Engine", f"{ep_count} endpoints", bool(ep_count))
            _print_js_findings(js_findings)

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      TimeElapsedColumn(), console=console, transient=True) as p:
            p.add_task("[cyan]Secret scanner...", total=None)
            secrets = await secret_engine.scan_all(assets)
        all_findings.extend(secrets)
        _status_line("Secrets", f"{len(secrets)} secrets found", bool(secrets))

        # ── PHASE 2: CONCURRENT VULN ENGINES ────────────────────────────
        _phase_header("Phase 2", "All Vuln Engines — Firing Simultaneously", "⚡")

        if not skip_active:
            vuln_findings = await _run_vuln_engines(
                modules=ALL_MODULES,
                assets=assets,
                js_findings=js_findings,
                domain=domain,
                blind_xss=blind_xss,
                oob_server=oob_server,
            )
            all_findings.extend(vuln_findings)
        else:
            console.print("[dim]⏩ Phase 2 skipped (passive mode)[/dim]\n")

        # ── PHASE 3: SCREENSHOTS (optional) ─────────────────────────────
        if screenshots:
            _phase_header("Phase 3", "Headless Screenshots", "📸")
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          TimeElapsedColumn(), console=console, transient=True) as p:
                p.add_task("[cyan]Capturing screenshots...", total=None)
                screen_engine = ScreenshotEngine()
                screen_results = await screen_engine.capture_all(subdomains, concurrency=4)
            results["screenshots"] = screen_results
            _status_line("Screenshots", f"{len(screen_results)} captured", bool(screen_results))

        # ── Risk Scoring ─────────────────────────────────────────────────
        prioritized = prioritize(all_findings)
        results["findings"] = prioritized

        if ai_report and prioritized:
            top = [f for f in prioritized if f.get("risk_score", 0) >= 6.0][:20]
            results["triaged_findings"] = ai.triage_findings(top)

        return results

    final = asyncio.run(run())

    elapsed = time.time() - scan_start
    _phase_header("Phase 4", "Saving Structured Results", "💾")

    scan_info = save_structured_results(final, output_dir)
    scan_dir  = scan_info["scan_dir"]
    meta      = scan_info["meta"]

    _print_findings(final.get("findings", []))

    console.print()
    console.print(Panel(
        f"[bold white]📁 Results[/bold white]   : [bold cyan]{scan_dir}[/bold cyan]\n\n"
        f"[bold white]🌐 Subdomains[/bold white]: {meta['live_subdomains']} alive / {meta['total_subdomains']} total\n"
        f"[bold white]📦 Assets[/bold white]    : {meta['total_assets']}\n"
        f"[bold white]🔍 Findings[/bold white]  : {meta['total_findings']} total  "
        f"[red]🔴 {meta['critical_count']} Critical[/red]  [orange3]🟠 {meta['high_count']} High[/orange3]\n"
        f"[bold white]⏱  Duration[/bold white]  : {elapsed:.1f}s\n\n"
        f"[dim]Quick access:[/dim]\n"
        f"  [cyan]cat {scan_dir}/01_subdomains/alive.txt[/cyan]\n"
        f"  [cyan]cat {scan_dir}/04_vulnerabilities/critical.json[/cyan]\n"
        f"  [cyan]open {scan_dir}/06_reports/summary_report.md[/cyan]",
        title="[bold gold1]♛ KING — Full Scan Complete[/bold gold1]  ⚡",
        border_style="bold red",
        padding=(1, 2),
    ))


# ══════════════════════════════════════════════════════════════════════════════
#  INFO COMMAND
# ══════════════════════════════════════════════════════════════════════════════

@app.command()
def info():
    """Show KING platform information and all available modules."""
    print_king_banner()
    console.print(Panel(
        "[bold white]KING[/bold white] is an elite, modular bug bounty automation platform.\n\n"
        "[bold cyan]Phase 1 — Recon (Sequential)[/bold cyan]:\n"
        "  • [cyan]subdomain[/cyan]          — Passive (subfinder, crt.sh, amass) + Active DNS brute-force + CertStream\n"
        "  • [cyan]osint[/cyan]              — GitHub code leaks, Shodan, Hunter.io email recon\n"
        "  • [cyan]crawler[/cyan]            — BFS/DFS crawler with directory brute-force\n"
        "  • [cyan]js[/cyan]                 — JS endpoint + secret extraction, source map analysis\n"
        "  • [cyan]secrets[/cyan]            — Entropy + regex secret detection\n\n"
        "[bold cyan]Phase 2 — Vuln Analysis (All CONCURRENT in full-scan)[/bold cyan]:\n"
        "  • [cyan]xss[/cyan]                — Reflected, DOM, and Blind XSS\n"
        "  • [cyan]ssrf[/cyan]               — Deep SSRF with OOB detection\n"
        "  • [cyan]bypass_403[/cyan]         — Header + path 403/401 bypass\n"
        "  • [cyan]idor[/cyan]               — BOLA/IDOR and mass assignment\n"
        "  • [cyan]jwt_csrf[/cyan]           — JWT algorithm confusion + CSRF analysis\n"
        "  • [cyan]cors[/cyan]               — CORS origin reflection + subdomain trust\n"
        "  • [cyan]business_logic[/cyan]     — Race conditions, coupon abuse, privilege confusion\n"
        "  • [cyan]prototype_pollution[/cyan]— JS + server-side prototype pollution\n"
        "  • [cyan]ai_prompt_injection[/cyan]— System prompt leak + jailbreak testing\n"
        "  • [cyan]mcp_security[/cyan]       — MCP tool schema disclosure + unauthorized execution\n"
        "  • [cyan]data_search[/cyan]        — Google dorks + GitHub deep search\n\n"
        "[bold cyan]Commands[/bold cyan]:\n"
        "  [bold]king scan example.com[/bold]               → Standard scan (10 modules)\n"
        "  [bold]king full-scan example.com[/bold]          → ALL engines, Phase 2 concurrent\n"
        "  [bold]king full-scan example.com --screenshots[/bold] → + headless screenshots\n"
        "  [bold]king full-scan example.com --ai-report[/bold]   → + AI-powered reports\n\n"
        "[bold cyan]Output[/bold cyan]:\n"
        "  Auto-saved → [cyan]./king_results/<domain>_<timestamp>/[/cyan]\n"
        "  01_subdomains/ | 02_assets/ | 03_secrets/ | 04_vulnerabilities/ | 05_osint/ | 06_reports/\n",
        title="[bold gold1]♛ KING — Elite Recon Platform[/bold gold1]",
        border_style="gold1",
        padding=(1, 2),
    ))


if __name__ == "__main__":
    app()
