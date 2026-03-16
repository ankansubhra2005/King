"""
Phase 2 - Prototype Pollution Detection Engine
Detects client-side JS prototype pollution patterns and server-side
(Node.js) prototype pollution via request parameter injection.
"""
import asyncio
import httpx
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, urlencode, parse_qs


# ── Known Prototype Pollution Sinks (Client-Side JS) ─────────────────────────

JS_POLLUTION_PATTERNS = [
    # Direct prototype manipulation
    (r"__proto__\s*[\[.]", "Direct __proto__ assignment"),
    (r"constructor\.prototype\s*[\[.]", "constructor.prototype manipulation"),
    (r"Object\.prototype\s*[\[.]", "Object.prototype manipulation"),
    # jQuery gadgets
    (r"jQuery\.extend\s*\(\s*true", "jQuery deep extend (pollution gadget)"),
    (r"\$\.extend\s*\(\s*true", "$.extend deep merge (pollution gadget)"),
    # lodash / merge gadgets
    (r"_\.merge\s*\(", "lodash _.merge (pollution gadget)"),
    (r"_\.defaultsDeep\s*\(", "lodash _.defaultsDeep (pollution gadget)"),
    (r"merge\s*\([^)]*,\s*[^)]*\)", "Generic deep merge call"),
    # Object.assign chains
    (r"Object\.assign\s*\(\s*\{\s*\}[^)]*\)", "Object.assign with empty target"),
    # json parsing fed into merge-like ops
    (r"JSON\.parse\s*\([^)]*\)\s*[^;]*merge|assign", "JSON.parse result fed into merge"),
]

# ── Server-Side Prototype Pollution Payloads ──────────────────────────────────

# These payloads are sent as JSON body — if the server merges user input into
# a global/shared object, the __proto__ key poisons the prototype chain.
SERVER_POLLUTION_PAYLOADS = [
    {"__proto__": {"polluted": "true"}},
    {"constructor": {"prototype": {"polluted": "true"}}},
    {"__proto__[polluted]": "true"},
    {"constructor[prototype][polluted]": "true"},
]

# Query-string keys that may trigger parsing-based gadgets
QS_POLLUTION_KEYS = [
    "__proto__[polluted]",
    "constructor[prototype][polluted]",
    "__proto__.polluted",
]

# Gadget-triggered indicators in responses
POLLUTION_INDICATORS = [
    "polluted",
    "__proto__",
    "prototype pollution",
    "cannot set property",
]


class PrototypePollutionEngine:
    """
    Detects prototype pollution vulnerabilities in both client-side JS code
    and server-side API endpoints.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    # ── Static JS Analysis ────────────────────────────────────────────────

    def scan_js_source(self, js_content: str, source_url: str) -> List[Dict]:
        """
        Scan a JS file's source code for prototype pollution patterns.
        Returns findings with line numbers and code snippets.
        """
        findings = []
        lines = js_content.split("\n")
        for i, line in enumerate(lines, 1):
            for pattern, description in JS_POLLUTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "type": "Prototype Pollution — JS Gadget",
                        "url": source_url,
                        "pattern": description,
                        "line": i,
                        "code_snippet": line.strip()[:250],
                        "severity": "medium",
                        "confidence": 0.65,
                        "evidence": f"Pattern '{pattern}' matched on line {i}",
                        "suggested_next_step": (
                            "Manually test if user-controlled input reaches "
                            "this merge/assign call. Use browser console: "
                            "({}).polluted !== undefined after sending payload."
                        ),
                    })
        return findings

    # ── Server-Side Probing ───────────────────────────────────────────────

    async def test_json_body(self, url: str, method: str = "POST") -> List[Dict]:
        """
        Inject prototype pollution payloads as JSON request bodies.
        Looks for reflection, errors, or pollution indicators in the response.
        """
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            for payload in SERVER_POLLUTION_PAYLOADS:
                try:
                    resp = await client.request(
                        method, url,
                        json=payload,
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            "Content-Type": "application/json",
                        },
                    )
                    body = resp.text[:500].lower()
                    if any(ind in body for ind in POLLUTION_INDICATORS):
                        findings.append({
                            "type": "Prototype Pollution — Server-Side (JSON Body)",
                            "url": url,
                            "payload": payload,
                            "status_code": resp.status_code,
                            "severity": "high",
                            "confidence": 0.75,
                            "evidence": f"Response contains pollution indicator after injecting {list(payload.keys())[0]}",
                            "suggested_next_step": (
                                "Confirm using a callback canary: send __proto__[toString] "
                                "and check if subsequent requests error or behave differently."
                            ),
                        })
                except Exception:
                    pass
        return findings

    async def test_query_string(self, url: str) -> List[Dict]:
        """
        Append prototype pollution keys to the query string.
        Useful for GET endpoints with qs library parsing (qs, express).
        """
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
            for key in QS_POLLUTION_KEYS:
                test_url = f"{base}?{key}=true"
                try:
                    resp = await client.get(test_url, headers={"User-Agent": "Mozilla/5.0"})
                    body = resp.text[:500].lower()
                    if any(ind in body for ind in POLLUTION_INDICATORS):
                        findings.append({
                            "type": "Prototype Pollution — Server-Side (Query String)",
                            "url": test_url,
                            "pollution_key": key,
                            "status_code": resp.status_code,
                            "severity": "high",
                            "confidence": 0.70,
                            "evidence": f"Response indicates pollution via key: {key}",
                            "suggested_next_step": "Test RCE gadgets: __proto__[env][NODE_OPTIONS]",
                        })
                except Exception:
                    pass
        return findings

    async def test_dom_pollution(self, url: str) -> Optional[Dict]:
        """
        Probe for client-side DOM clobbering via URL fragment/hash injection.
        Tests if '#__proto__[polluted]=1' reaches JS code.
        """
        # This is a static signal — we can't run JS headlessly here.
        # Return an actionable finding for manual follow-up.
        return {
            "type": "Prototype Pollution — DOM (Manual Verification Required)",
            "url": url,
            "test_url": f"{url}#__proto__[polluted]=1",
            "severity": "medium",
            "confidence": 0.50,
            "evidence": "Hash-based prototype pollution requires browser validation",
            "suggested_next_step": (
                f"Open {url}#__proto__[polluted]=1 in browser, then run: "
                "console.log(({}).polluted) — if 'true', pollution confirmed."
            ),
        }

    async def scan(self, assets: List[Dict], js_findings: List[Dict] = None) -> List[Dict]:
        """Full prototype pollution scan over assets and JS files — STRICTLY SEQUENTIAL."""
        all_findings = []

        # 1. Static analysis on all fetched JS
        for jf in (js_findings or []):
            content = jf.get("content", "")
            if content:
                all_findings.extend(self.scan_js_source(content, jf.get("url", "")))

        # 2. Server-side probing on API-like endpoints or URLs with params
        api_assets = [
            a for a in assets
            if (any(kw in a.get("url", "").lower() for kw in ["/api/", "/v1/", "/v2/", "graphql", "/json"])
                or parse_qs(urlparse(a.get("url", "")).query))
        ]
        for asset in api_assets[:20]:  # Limit to prevent flooding
            url = asset.get("url", "")
            # Test JSON body (if API-like)
            if any(kw in url.lower() for kw in ["/api/", "/v1/", "/v2/", "graphql", "/json"]):
                json_res = await self.test_json_body(url, "POST")
                all_findings.extend(json_res)
            # Test Query String
            qs_res = await self.test_query_string(url)
            all_findings.extend(qs_res)

        return all_findings
