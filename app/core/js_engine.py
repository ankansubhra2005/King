"""
Module 4: JS Intelligence Engine
Downloads JS files, extracts endpoints, and performs source map analysis.
"""
import asyncio
import re
import httpx
import jsbeautifier
import json
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse


# ── Patterns ───────────────────────────────────────────────────────────────

ENDPOINT_PATTERNS = [
    r"""(?:"|')(/(?:api|v\d+|graphql|rest|gql|internal)[^"'<>]{1,200})(?:"|')""",  # /api/... paths
    r"""(?:"|')((?:http|https)://[^"'<>]{1,200})(?:"|')""",                          # full URLs
    r"""(?:fetch|axios|\.get|\.post|\.put|\.delete)\s*\(\s*['"](.*?)['"]""",         # fetch/axios calls
    r"""url\s*:\s*['"](.*?)['"]""",                                                   # url: "..." configs
    r"""path\s*:\s*['"](.*?)['"]""",                                                  # path: "..."
    r"""endpoint\s*:\s*['"](.*?)['"]""",                                              # endpoint: "..."
    r"""WebSocket\s*\(\s*['"](.*?)['"]""",                                            # WebSocket URLs
    r"""graphql\s*\(\s*\{[^}]*uri\s*:\s*['"](.*?)['"]""",                            # Apollo GraphQL uri
]

SENSITIVE_IMPORT_PATTERNS = [
    r"""require\s*\(\s*['"](.*?)['"]""",    # CommonJS imports
    r"""import\s.*?from\s*['"](.*?)['"]""", # ES module imports
]


class JSEngine:
    def __init__(self):
        self.timeout = 15

    # ── Download ───────────────────────────────────────────────────────────

    async def download_js(self, url: str) -> Optional[str]:
        """Download and beautify a JS file."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    return jsbeautifier.beautify(resp.text)
        except Exception:
            pass
        return None

    async def resolve_source_map(self, js_url: str, js_content: str) -> Optional[dict]:
        """
        Attempt to download *.js.map file and recover original source code.
        Maps expose the original pre-minification source — huge for bug bounty.
        """
        map_url = js_url + ".map"
        # Also check //# sourceMappingURL= comment
        match = re.search(r"//# sourceMappingURL=(.+)", js_content)
        if match:
            map_ref = match.group(1).strip()
            if not map_ref.startswith("http"):
                map_url = urljoin(js_url, map_ref)

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                resp = await client.get(map_url)
                if resp.status_code == 200:
                    map_data = resp.json()
                    return {
                        "map_url": map_url,
                        "sources": map_data.get("sources", []),
                        "source_count": len(map_data.get("sources", [])),
                    }
        except Exception:
            pass
        return None

    # ── Endpoint Extraction ────────────────────────────────────────────────

    def extract_endpoints(self, js_content: str, base_url: str = "") -> List[Dict]:
        """Extract API endpoints and URLs from JS source."""
        found = []
        seen = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                endpoint = match.group(1).strip()
                if endpoint and endpoint not in seen:
                    seen.add(endpoint)
                    full_url = urljoin(base_url, endpoint) if endpoint.startswith("/") else endpoint
                    found.append({
                        "raw": endpoint,
                        "full_url": full_url,
                        "type": self._classify_endpoint(endpoint),
                    })
        return found

    def _classify_endpoint(self, ep: str) -> str:
        if "graphql" in ep.lower() or "gql" in ep.lower():
            return "graphql"
        if "websocket" in ep.lower() or ep.startswith("ws"):
            return "websocket"
        if re.search(r"v\d+", ep):
            return "rest_api"
        return "path"

    def extract_imports(self, js_content: str) -> List[str]:
        """Extract all import/require statements to map dependencies."""
        imports = set()
        for p in SENSITIVE_IMPORT_PATTERNS:
            for m in re.finditer(p, js_content, re.IGNORECASE):
                imports.add(m.group(1))
        return list(imports)

    # ── Inline Script Extraction ────────────────────────────────────────────

    def extract_inline_scripts(self, html: str) -> List[str]:
        """Extract inline <script> content from HTML."""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "lxml")
        scripts = []
        for tag in soup.find_all("script"):
            if not tag.get("src") and tag.string:
                scripts.append(tag.string)
        return scripts

    # ── Main Entry Point ────────────────────────────────────────────────────

    async def analyze(self, asset: Dict) -> Dict:
        """Analyze a single JS asset."""
        url = asset["url"]
        content = await self.download_js(url)
        if not content:
            return {"url": url, "error": "download_failed"}

        endpoints = self.extract_endpoints(content, base_url=url)
        imports = self.extract_imports(content)
        source_map = await self.resolve_source_map(url, content)

        return {
            "url": url,
            "endpoints": endpoints,
            "imports": imports,
            "source_map": source_map,
            "line_count": content.count("\n"),
        }

    async def analyze_all(self, js_assets: List[Dict]) -> List[Dict]:
        """Analyze all discovered JS assets concurrently."""
        sem = asyncio.Semaphore(10)
        results = []

        async def bounded_analyze(asset):
            async with sem:
                return await self.analyze(asset)

        results = await asyncio.gather(*[bounded_analyze(a) for a in js_assets])
        return [r for r in results if r]
