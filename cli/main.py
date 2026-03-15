"""
Entry point for the Bug Bounty Recon Platform CLI.
Usage: python -m cli.main [command]
"""
import typer
import asyncio
import json
import os
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
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
from app.core.risk_engine import prioritize
from app.core.osint_engine import OSINTEngine
from app.core.ai_triage import AITriageEngine

app = typer.Typer(
    name="recon",
    help="🎯 Bug Bounty Recon Platform — Elite Automated Recon Tool",
    add_completion=True,
)
console = Console()


@app.command(name="scan")
def scan(
    domain: str = typer.Argument(..., help="Target domain (e.g. example.com)"),
    in_scope: Optional[List[str]] = typer.Option(None, "--scope", "-s", help="In-scope rules"),
    out_of_scope: Optional[List[str]] = typer.Option(None, "--exclude", "-e", help="Out-of-scope rules"),
    modules: Optional[List[str]] = typer.Option(
        ["subdomain", "osint", "crawler", "js", "secrets", "xss", "ssrf", "bypass_403", "idor", "jwt_csrf"],
        "--module", "-m", help="Modules to run"
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (.json or .md)"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir", "-d", help="Output directory for structured results"),
    passive: bool = typer.Option(False, "--passive", help="Passive mode only"),
    threads: int = typer.Option(30, "--threads", "-t", help="Thread count"),
    blind_xss: Optional[str] = typer.Option(None, "--blind-xss", help="Blind XSS callback URL"),
    oob_server: Optional[str] = typer.Option(None, "--oob", help="OOB callback server for SSRF"),
    ai_report: bool = typer.Option(False, "--ai-report", help="Generate AI-powered reports for high findings"),
):
    """
    Run a full recon scan + vulnerability analysis against a target domain.

    Examples:
    \b
        recon scan example.com
        recon scan example.com --module subdomain --module xss --blind-xss https://cb.example.net
        recon scan example.com --passive --output results.json
        recon scan example.com --ai-report --output report.md
    """
    scope_rules = in_scope or [f"*.{domain}", domain]
    scope = ScopeFilter(in_scope=scope_rules, out_of_scope=out_of_scope or [])
    results = {"domain": domain, "findings": [], "subdomains": [], "assets": []}

    console.print(Panel.fit(
        f"[bold cyan]🎯 Bug Bounty Recon Platform[/bold cyan]\n"
        f"[dim]Target:[/dim] [green]{domain}[/green]  "
        f"[dim]Modules:[/dim] [yellow]{', '.join(modules)}[/yellow]",
        border_style="cyan"
    ))

    async def run():
        recon = ReconEngine(domain=domain, scope=scope, threads=threads)
        crawler = Crawler(scope=scope, threads=threads)
        js_engine = JSEngine()
        secret_engine = SecretEngine()
        osint = OSINTEngine()
        ai = AITriageEngine()

        all_findings = []
        subdomains, assets, js_findings = [], [], []

        # ── Phase 1 ──────────────────────────────────────────────────────
        if "subdomain" in modules:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as p:
                p.add_task("Enumerating subdomains...", total=None)
                recon_results = await recon.enumerate(passive_only=passive)
            
            subdomains = recon_results.get("subdomains", [])
            results["subdomains"] = subdomains
            
            if passive:
                assets = recon_results.get("assets", [])
                results["assets"] = assets
                console.print(f"[bold cyan]🔍 Found {len(assets)} passive assets from historical data[/bold cyan]")
                
            _print_subdomains(subdomains)

        if "osint" in modules and subdomains:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as p:
                p.add_task("Running OSINT (Shodan + GitHub)...", total=None)
                osint_data = await osint.scan(domain, subdomains)
            all_findings.extend(osint_data.get("github_leaks", []))
            gh_count = len(osint_data.get("github_leaks", []))
            if gh_count:
                console.print(f"[bold red]🐙 Found {gh_count} potential GitHub leaks![/bold red]")
            else:
                console.print(f"[green]✅ OSINT complete (no leaks found)[/green]")

        if "crawler" in modules and subdomains and not passive:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as p:
                p.add_task("Crawling + directory brute-forcing...", total=None)
                assets = await crawler.crawl_all(subdomains)
            results["assets"] = assets
            console.print(f"[green]✅ Discovered {len(assets)} assets[/green]")

        if "js" in modules:
            js_assets = [a for a in assets if a.get("type") == "js"]
            if js_assets:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as p:
                    p.add_task(f"Analyzing {len(js_assets)} JS files...", total=None)
                    js_findings = await js_engine.analyze_all(js_assets)
                results["js_findings"] = js_findings
                ep_count = sum(len(j.get("endpoints", [])) for j in js_findings)
                console.print(f"[green]✅ Extracted {ep_count} endpoints from JS[/green]")
                _print_js_findings(js_findings)
            else:
                console.print(f"[dim]JS analysis skipped: no JS assets found[/dim]")

        if "secrets" in modules:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as p:
                p.add_task("Scanning for secrets...", total=None)
                secrets = await secret_engine.scan_all(assets)
            all_findings.extend(secrets)
            if secrets:
                console.print(f"[bold red]🔑 Found {len(secrets)} secrets![/bold red]")
            else:
                console.print(f"[green]✅ Secret scan complete (no secrets found)[/green]")

        # ── Phase 2 Vuln Engine ───────────────────────────────────────────
        if not passive:
            if "xss" in modules:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as p:
                    p.add_task("Testing XSS (reflected + DOM + blind)...", total=None)
                    xss = await XSSEngine(blind_xss_url=blind_xss).scan(assets, js_findings)
                all_findings.extend(xss)
                if xss:
                    console.print(f"[bold red]💉 Found {len(xss)} XSS vulnerabilities![/bold red]")
                else:
                    console.print(f"[green]✅ XSS scan complete[/green]")

            if "ssrf" in modules:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as p:
                    p.add_task("Testing SSRF...", total=None)
                    ssrf = await SSRFEngine(oob_server=oob_server).scan(assets)
                all_findings.extend(ssrf)
                if ssrf:
                    console.print(f"[bold red]🔗 Found {len(ssrf)} SSRF vulnerabilities![/bold red]")
                else:
                    console.print(f"[green]✅ SSRF scan complete[/green]")

            if "bypass_403" in modules:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as p:
                    p.add_task("Testing 403/401 bypass...", total=None)
                    bypass = await FourOhThreeBypass().scan(assets)
                all_findings.extend(bypass)
                if bypass:
                    console.print(f"[bold yellow]🔓 Found {len(bypass)} bypasses![/bold yellow]")
                else:
                    console.print(f"[green]✅ 403 scan complete[/green]")

            if "idor" in modules:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as p:
                    p.add_task("Testing IDOR + mass assignment...", total=None)
                    idor = await IDOREngine().scan(assets)
                all_findings.extend(idor)
                if idor:
                    console.print(f"[bold yellow]👤 Found {len(idor)} IDOR issues![/bold yellow]")
                else:
                    console.print(f"[green]✅ IDOR scan complete[/green]")

            if "jwt_csrf" in modules:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as p:
                    p.add_task("Analyzing JWT + CSRF...", total=None)
                    csrf = await CSRFEngine().scan(assets)
                all_findings.extend(csrf)
                if csrf:
                    console.print(f"[bold yellow]🍪 Found {len(csrf)} CSRF/JWT issues![/bold yellow]")
                else:
                    console.print(f"[green]✅ Auth scan complete[/green]")
        else:
            console.print("[dim]Phase 2 skipped (passive mode enabled)[/dim]")

        # ── Risk Scoring ─────────────────────────────────────────────────
        prioritized = prioritize(all_findings)
        results["findings"] = prioritized

        if ai_report and prioritized:
            top = [f for f in prioritized if f.get("risk_score", 0) >= 6.0][:20]
            results["triaged_findings"] = ai.triage_findings(top)

        _print_findings(prioritized)
        return results

    final = asyncio.run(run())

    if output:
        if output.endswith(".json"):
            with open(output, "w") as f:
                json.dump(final, f, indent=2, default=str)
        elif output.endswith(".md"):
            _write_markdown(final, output)
        console.print(f"\n[bold green]💾 Results saved to {output}[/bold green]")

    if output_dir:
        _save_to_directory(final, output_dir)
        console.print(f"\n[bold green]📂 Results saved to structured directory: {output_dir}[/bold green]")

    console.print("\n[bold green]✅ Scan complete![/bold green]")


# ── Print Helpers ─────────────────────────────────────────────────────────────

def _print_subdomains(subdomains: List[dict]):
    alive = [s for s in subdomains if s.get("is_alive")]
    table = Table(title=f"Subdomains — {len(alive)} alive", show_lines=False)
    table.add_column("FQDN", style="cyan", min_width=30)
    table.add_column("Status", style="green")
    table.add_column("Title", style="dim", max_width=40)
    table.add_column("CDN", style="yellow")
    table.add_column("WAF", style="red")
    for s in alive[:50]:
        table.add_row(s.get("fqdn",""), str(s.get("status_code","")), s.get("title","") or "",
                      s.get("cdn_name","") or "", s.get("waf_detected","") or "")
    console.print(table)


def _print_findings(findings: List[dict]):
    if not findings:
        console.print("[dim]No findings.[/dim]")
        return
    table = Table(title=f"🔍 Findings — Top {min(len(findings),30)} by Risk Score", show_lines=True)
    table.add_column("Score", style="red", min_width=6)
    table.add_column("Severity", style="bold", min_width=8)
    table.add_column("Type", style="yellow", min_width=25)
    table.add_column("URL", style="cyan", max_width=55)
    table.add_column("Why", style="dim", max_width=45)
    for f in findings[:30]:
        score = str(f.get("risk_score", ""))
        sev = f.get("severity", "info").upper()
        sev_color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green", "INFO": "dim"}.get(sev, "white")
        table.add_row(
            score,
            Text(sev, style=sev_color),
            f.get("type", "")[:35],
            f.get("url", "")[:55],
            f.get("why_it_matters", "")[:45],
        )
    console.print(table)


def _print_js_findings(js_findings: List[dict]):
    if not js_findings:
        return
    table = Table(title=f"📜 JavaScript Analysis — {len(js_findings)} files", show_lines=False)
    table.add_column("File", style="cyan")
    table.add_column("Endpoints", style="green")
    table.add_column("Secrets", style="red")
    for j in js_findings[:20]:
        eps = len(j.get("endpoints", []))
        secrets = len(j.get("secrets", []))
        table.add_row(j.get("url", "")[-50:], str(eps), str(secrets))
    console.print(table)


def _write_markdown(results: dict, path: str):
    lines = [f"# Recon Report: {results['domain']}\n\n"]
    lines.append(f"## Subdomains ({len(results.get('subdomains',[]))} found)\n")
    for s in results.get("subdomains", []):
        if s.get("is_alive"):
            lines.append(f"- `{s['fqdn']}` — {s.get('status_code')} — {s.get('title','')}\n")
    lines.append(f"\n## Findings ({len(results.get('findings',[]))} total)\n")
    for f in results.get("findings", []):
        lines.append(f"\n### [{f.get('risk_score',0)}/10] {f.get('type','')}\n")
        lines.append(f"- **URL**: `{f.get('url','')}`\n")
        lines.append(f"- **Severity**: {f.get('severity','').upper()}\n")
        lines.append(f"- **Why**: {f.get('why_it_matters','')}\n")
        lines.append(f"- **Next Step**: {f.get('suggested_next_step','')}\n")
        if f.get("ai_report"):
            lines.append(f"\n{f['ai_report']}\n")
    with open(path, "w") as f:
        f.writelines(lines)


def _save_to_directory(results: dict, dir_path: str):
    """Save scan results into a structured directory with multiple files."""
    if not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)
    
    # helper for nested dirs
    def ensure_dir(name):
        d = os.path.join(dir_path, name)
        if not os.path.exists(d): os.makedirs(d, exist_ok=True)
        return d

    # 1. Subdomains
    sub_dir = ensure_dir("subdomains")
    subdomains = results.get("subdomains", [])
    with open(os.path.join(sub_dir, "all_live.json"), "w") as f:
        json.dump(subdomains, f, indent=2, default=str)
    
    with open(os.path.join(sub_dir, "active_bruteforce.txt"), "w") as f:
        for s in subdomains:
            if "active:bruteforce" in s.get("sources", []):
                f.write(f"{s.get('fqdn')}\n")
                
    with open(os.path.join(sub_dir, "passive.txt"), "w") as f:
        for s in subdomains:
            if any(src.startswith("passive:") for src in s.get("sources", [])):
                f.write(f"{s.get('fqdn')}\n")

    with open(os.path.join(sub_dir, "all_hosts.txt"), "w") as f:
        for s in subdomains:
            f.write(f"{s.get('fqdn')}\n")
    
    # 2. Assets & JS
    assets_dir = ensure_dir("assets")
    js_dir = ensure_dir("js")
    assets = results.get("assets", [])
    with open(os.path.join(assets_dir, "all_assets.json"), "w") as f:
        json.dump(assets, f, indent=2, default=str)
    
    with open(os.path.join(assets_dir, "urls.txt"), "w") as f:
        for a in assets:
            if "url" in a: f.write(f"{a['url']}\n")

    js_findings = results.get("js_findings", [])
    if js_findings:
        with open(os.path.join(js_dir, "js_analysis.json"), "w") as f:
            json.dump(js_findings, f, indent=2, default=str)
        with open(os.path.join(js_dir, "endpoints.txt"), "w") as f:
            for j in js_findings:
                for ep in j.get("endpoints", []):
                    f.write(f"{ep}\n")

    # 3. Vulnerabilities
    vuln_dir = ensure_dir("vulns")
    findings = results.get("findings", [])
    with open(os.path.join(vuln_dir, "all_findings.json"), "w") as f:
        json.dump(findings, f, indent=2, default=str)
    
    # Group findings by type/severity
    secret_keywords = ["secret", "key", "token", "webhook", "cred", "password"]
    for ftype in ["xss", "ssrf", "secrets", "idor", "auth"]:
        if ftype == "secrets":
            typed = [f for f in findings if any(k in f.get("type", "").lower() for k in secret_keywords)]
        elif ftype == "auth":
            typed = [f for f in findings if any(x in f.get("type","").lower() for x in ["jwt", "csrf", "broken auth"])]
        else:
            typed = [f for f in findings if ftype in f.get("type", "").lower()]
            
        if typed:
            with open(os.path.join(vuln_dir, f"{ftype}.json"), "w") as f:
                json.dump(typed, f, indent=2, default=str)

    # 4. Global Report
    _write_markdown(results, os.path.join(dir_path, "summary_report.md"))

@app.command()
def info():
    """Show platform information."""
    console.print("[bold cyan]🎯 Bug Bounty Recon Platform v1.0[/bold cyan]")


if __name__ == "__main__":
    app()
