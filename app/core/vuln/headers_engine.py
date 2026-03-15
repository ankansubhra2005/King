"""
Phase 2 - Module 9: Security Headers Analysis Engine
Analyzes missing or weak security headers (OWASP A05:2021-Security Misconfiguration).
"""
import asyncio
import httpx
from typing import List, Dict, Optional

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "medium",
        "owasp": "A03:2021-Injection",
        "desc": "Missing CSP — helps prevent XSS and injection attacks",
    },
    "Strict-Transport-Security": {
        "severity": "low",
        "owasp": "A02:2021-Cryptographic Failures",
        "desc": "Missing HSTS — prevents protocol downgrade attacks",
    },
    "X-Frame-Options": {
        "severity": "low",
        "owasp": "A05:2021-Security Misconfiguration",
        "desc": "Missing XFO — helps prevent Clickjacking",
    },
    "X-Content-Type-Options": {
        "severity": "info",
        "owasp": "A05:2021-Security Misconfiguration",
        "desc": "Missing X-Content-Type-Options — prevents MIME sniffing",
    },
    "Referrer-Policy": {
        "severity": "info",
        "owasp": "A05:2021-Security Misconfiguration",
        "desc": "Missing Referrer-Policy",
    },
    "Permissions-Policy": {
        "severity": "info",
        "owasp": "A05:2021-Security Misconfiguration",
        "desc": "Missing Permissions-Policy (Feature-Policy successor)",
    }
}

class HeadersEngine:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def check_headers(self, url: str) -> List[Dict]:
        """Fetch headers and check for missing security-related ones."""
        findings = []
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                headers = {k.lower(): v for k, v in resp.headers.items()}
                
                for head, info in SECURITY_HEADERS.items():
                    if head.lower() not in headers:
                        findings.append({
                            "type": f"Missing Security Header: {head}",
                            "url": url,
                            "severity": info["severity"],
                            "confidence": 1.0, # Fact: it's missing
                            "evidence": f"Header '{head}' not found in response",
                            "owasp_category": info["owasp"],
                            "suggested_next_step": f"Implement the '{head}' header with secure values",
                            "source": "king-internal",
                        })
                    else:
                        # Optional: Check for weak values
                        val = headers[head.lower()].lower()
                        if head == "X-Frame-Options" and "allow" in val:
                            findings.append({
                                "type": f"Weak Security Header: {head}",
                                "url": url,
                                "severity": "low",
                                "confidence": 0.9,
                                "evidence": f"XFO set to weak value: {val}",
                                "owasp_category": "A05:2021-Security Misconfiguration",
                                "suggested_next_step": "Set X-Frame-Options to DENY or SAMEORIGIN",
                                "source": "king-internal",
                            })
        except Exception:
            pass
        return findings

    async def scan(self, subdomains: List[Dict]) -> List[Dict]:
        """Scan live hosts for missing security headers."""
        all_findings = []
        # Only scan alive subdomains
        live_urls = [f"https://{s['fqdn']}" for s in subdomains if s.get("is_alive")]
        
        if not live_urls:
            return []
            
        tasks = [self.check_headers(url) for url in live_urls[:20]] # Limit concurrency
        results = await asyncio.gather(*tasks)
        for r in results:
            all_findings.extend(r)
            
        return all_findings
