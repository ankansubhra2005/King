import asyncio
import os
from app.workers.celery_app import celery_app
from app.core.input_layer import ScopeFilter
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
from app.core.risk_engine import prioritize
from app.core.osint_engine import OSINTEngine
from app.core.ai_triage import AITriageEngine
from app.core.data_search import DataSearchEngine
from app.core.secret_validator import SecretValidator
from app.core.surface_mapper import AttackSurfaceMapper
from app.core.utils.deduplicator import Deduplicator
from app.core.utils.proxy_manager import ProxyManager


@celery_app.task(bind=True, name="run_scan_pipeline")
def run_scan_pipeline(self, scan_id: int, domain: str, config: dict):
    """
    Full recon pipeline — Phase 1 + Phase 2.

    Flow:
        Subdomain Enum → OSINT Enrichment → Crawl → Dir Bruteforce
        → JS Analysis → Secret Scan → Vuln Engine (XSS/SSRF/403/IDOR/JWT/CSRF)
        → Risk Scoring → AI Triage
    """
    modules = config.get("modules", [
        "subdomain", "osint", "crawler", "js", "secrets",
        "xss", "ssrf", "bypass_403", "idor", "jwt_csrf",
        "cors", "business_logic", "data_search"
    ])
    results = {"scan_id": scan_id, "domain": domain, "all_findings": []}

    scope = ScopeFilter(in_scope=config.get("in_scope", [f"*.{domain}", domain]))
    blind_xss = config.get("blind_xss_url") or os.getenv("BLIND_XSS_CALLBACK_URL", "")
    oob_server = config.get("oob_server", "")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def run(coro):
        return loop.run_until_complete(coro)

    # ── Phase 1 ──────────────────────────────────────────────────────────────
    subdomains = []
    if "subdomain" in modules:
        self.update_state(state="PROGRESS", meta={"step": "Subdomain enumeration"})
        subdomains = run(ReconEngine(domain, scope).enumerate())
        results["subdomains"] = subdomains

    if "osint" in modules and subdomains:
        self.update_state(state="PROGRESS", meta={"step": "OSINT enrichment"})
        osint_data = run(OSINTEngine().scan(domain, subdomains))
        results["osint"] = osint_data
        results["all_findings"].extend(osint_data.get("github_leaks", []))

    assets = []
    if "crawler" in modules and subdomains:
        self.update_state(state="PROGRESS", meta={"step": "Crawling + directory brute-force"})
        assets = run(Crawler(scope).crawl_all(subdomains))
        assets = Deduplicator.deduplicate_assets(assets)
        results["assets"] = assets

    js_findings = []
    if "js" in modules:
        self.update_state(state="PROGRESS", meta={"step": "JS analysis"})
        js_assets = [a for a in assets if a.get("type") == "js"]
        js_findings = run(JSEngine().analyze_all(js_assets))
        results["js_findings"] = js_findings

    if "secrets" in modules:
        self.update_state(state="PROGRESS", meta={"step": "Secret detection"})
        secrets = run(SecretEngine().scan_all(assets))
        # Validate found secrets (Phase 2 completion)
        secrets = run(SecretValidator().validate_all(secrets))
        results["all_findings"].extend(secrets)

    # ── Phase 2 Vuln Engine ──────────────────────────────────────────────────
    if "xss" in modules:
        self.update_state(state="PROGRESS", meta={"step": "XSS scan"})
        xss = run(XSSEngine(blind_xss_url=blind_xss or None).scan(assets, js_findings))
        results["all_findings"].extend(xss)

    if "ssrf" in modules:
        self.update_state(state="PROGRESS", meta={"step": "SSRF scan"})
        ssrf = run(SSRFEngine(oob_server=oob_server or None).scan(assets))
        results["all_findings"].extend(ssrf)

    if "bypass_403" in modules:
        self.update_state(state="PROGRESS", meta={"step": "403 bypass scan"})
        bypass = run(FourOhThreeBypass().scan(assets))
        results["all_findings"].extend(bypass)

    if "idor" in modules:
        self.update_state(state="PROGRESS", meta={"step": "IDOR scan"})
        idor = run(IDOREngine().scan(assets))
        results["all_findings"].extend(idor)

    if "jwt_csrf" in modules:
        self.update_state(state="PROGRESS", meta={"step": "JWT/CSRF analysis"})
        csrf = run(CSRFEngine().scan(assets))
        results["all_findings"].extend(csrf)

    if "cors" in modules:
        self.update_state(state="PROGRESS", meta={"step": "CORS detection"})
        cors = run(CORSEngine().scan(assets))
        results["all_findings"].extend(cors)

    if "business_logic" in modules:
        self.update_state(state="PROGRESS", meta={"step": "Business logic testing"})
        bl = run(BusinessLogicEngine().scan(domain, assets))
        results["all_findings"].extend(bl)

    if "data_search" in modules:
        self.update_state(state="PROGRESS", meta={"step": "Internet-wide data search"})
        ds = run(DataSearchEngine().scan(domain))
        results["all_findings"].extend(ds)

    # ── Risk Scoring + AI Triage ─────────────────────────────────────────────
    self.update_state(state="PROGRESS", meta={"step": "Risk prioritization"})
    # Deduplicate findings before scoring
    results["all_findings"] = Deduplicator.deduplicate_findings(results["all_findings"])
    results["all_findings"] = prioritize(results["all_findings"])

    top_findings = [f for f in results["all_findings"] if f.get("risk_score", 0) >= 6.0]
    if top_findings:
        self.update_state(state="PROGRESS", meta={"step": "AI triage"})
        results["triaged_findings"] = AITriageEngine().triage_findings(top_findings[:20])

    self.update_state(state="PROGRESS", meta={"step": "Generating attack surface map"})
    results["attack_surface"] = AttackSurfaceMapper.generate_graph(domain, subdomains, assets)

    loop.close()
    return results
