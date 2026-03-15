"""
Phase 2 (Additional) - Business Logic Engine
Tests for race conditions, rate limit bypasses, workflow skipping, and logic flaws.
"""
import asyncio
import httpx
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode


# ── Race Condition ────────────────────────────────────────────────────────────

class RaceConditionEngine:
    """
    Sends many identical requests simultaneously to detect race conditions.
    Targets: OTP submission, gift card redemption, coupon codes, voting.
    """
    RACE_COUNT = 20   # Number of simultaneous requests

    async def test(self, url: str, method: str = "POST",
                   data: Optional[dict] = None, headers: Optional[dict] = None) -> List[Dict]:
        """Fire multiple simultaneous requests to probe for race conditions."""
        h = {"User-Agent": "Mozilla/5.0", **(headers or {})}
        findings = []
        responses = []

        async def fire():
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    resp = await client.request(method, url, json=data, headers=h)
                    return {"status": resp.status_code, "body": resp.text[:200]}
            except Exception:
                return None

        # All fired at the same instant
        tasks = [fire() for _ in range(self.RACE_COUNT)]
        responses = await asyncio.gather(*tasks)
        responses = [r for r in responses if r]

        # Analyze: multiple 200s for a normally one-time action = race condition
        successes = [r for r in responses if r["status"] in [200, 201]]
        if len(successes) > 1:
            findings.append({
                "type": "Race Condition",
                "url": url,
                "concurrent_requests": self.RACE_COUNT,
                "successful_responses": len(successes),
                "severity": "high",
                "confidence": 0.75,
                "evidence": f"{len(successes)}/{self.RACE_COUNT} requests succeeded (expected 0 or 1)",
                "suggested_next_step": "Confirm double-spend or duplicate-action exploitability",
            })
        return findings


# ── Rate Limit Bypass ─────────────────────────────────────────────────────────

RATE_LIMIT_BYPASS_HEADERS = [
    {"X-Forwarded-For": "1.2.3.4"},
    {"X-Forwarded-For": "5.6.7.8"},
    {"X-Real-IP": "9.10.11.12"},
    {"X-Originating-IP": "13.14.15.16"},
    {"X-Remote-IP": "17.18.19.20"},
    {"CF-Connecting-IP": "21.22.23.24"},
]

class RateLimitBypassEngine:
    """Tests if rate limits can be bypassed using IP spoofing headers."""

    async def test(self, url: str, method: str = "POST",
                   data: Optional[dict] = None, threshold: int = 5) -> List[Dict]:
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for header_set in RATE_LIMIT_BYPASS_HEADERS:
                successes = 0
                for _ in range(threshold + 2):
                    try:
                        h = {"User-Agent": "Mozilla/5.0", **header_set}
                        resp = await client.request(method, url, json=data, headers=h)
                        if resp.status_code not in [429, 503]:
                            successes += 1
                        else:
                            break
                    except Exception:
                        break

                if successes > threshold:
                    findings.append({
                        "type": "Rate Limit Bypass",
                        "url": url,
                        "bypass_header": list(header_set.keys())[0],
                        "bypass_value": list(header_set.values())[0],
                        "requests_before_block": successes,
                        "severity": "medium",
                        "confidence": 0.80,
                        "evidence": f"Sent {successes} requests without hitting 429 using {list(header_set.keys())[0]}",
                        "suggested_next_step": "Use to bypass account lockout on login or OTP verification",
                    })
                    break  # Found one bypass, move on
        return findings


# ── Business Logic — Workflow Bypass ─────────────────────────────────────────

SENSITIVE_STEP_KEYWORDS = [
    "checkout", "payment", "confirm", "verify", "complete",
    "2fa", "mfa", "otp", "validate", "approve",
]


class WorkflowBypassEngine:
    """
    Tests if multi-step flows can be skipped.
    Strategy: identifies step-2+ URLs and directly accesses them without step-1.
    """

    def find_workflow_candidates(self, assets: List[Dict]) -> List[Dict]:
        """Find endpoints that look like later steps in a workflow."""
        candidates = []
        for asset in assets:
            url = asset.get("url", "").lower()
            if any(kw in url for kw in SENSITIVE_STEP_KEYWORDS):
                candidates.append(asset)
        return candidates

    async def test_direct_access(self, url: str) -> Optional[Dict]:
        """Try accessing a step URL directly without prior session state."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=False) as client:
                # Fresh session (no cookies)
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code in [200, 201]:
                    return {
                        "type": "Workflow Bypass (Potential)",
                        "url": url,
                        "status_code": resp.status_code,
                        "severity": "medium",
                        "confidence": 0.60,
                        "evidence": f"Direct access to {url} returned {resp.status_code} without prior session",
                        "suggested_next_step": "Test if completing this step without prior steps achieves unauthorized action",
                    }
        except Exception:
            pass
        return None


# ── Cloud Bucket Discovery ─────────────────────────────────────────────────────

BUCKET_PROVIDERS = {
    "AWS S3":    "https://{name}.s3.amazonaws.com/",
    "GCS":       "https://storage.googleapis.com/{name}/",
    "Azure":     "https://{name}.blob.core.windows.net/",
    "S3 subdomain": "https://s3.amazonaws.com/{name}/",
}

BUCKET_SUFFIXES = [
    "", "-prod", "-staging", "-dev", "-backup", "-data",
    "-assets", "-static", "-files", "-media", "-public",
    "-uploads", "-logs", "-internal",
]


class BucketDiscovery:
    """Enumerate and probe cloud storage buckets related to the target."""

    async def discover(self, domain: str) -> List[Dict]:
        name = domain.split(".")[0]  # "example" from "example.com"
        candidates = [f"{name}{s}" for s in BUCKET_SUFFIXES]
        findings = []
        sem = asyncio.Semaphore(20)

        async def probe(bucket_name: str, provider: str, url_template: str):
            url = url_template.format(name=bucket_name)
            async with sem:
                try:
                    async with httpx.AsyncClient(verify=False, timeout=8, follow_redirects=True) as client:
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            findings.append({
                                "type": "Open Cloud Bucket",
                                "url": url,
                                "bucket_name": bucket_name,
                                "provider": provider,
                                "status_code": 200,
                                "severity": "high",
                                "confidence": 0.90,
                                "evidence": "Bucket accessible without authentication",
                                "suggested_next_step": "Download and inspect contents for sensitive files",
                            })
                        elif resp.status_code == 403:
                            findings.append({
                                "type": "Existing Cloud Bucket (Private)",
                                "url": url,
                                "bucket_name": bucket_name,
                                "provider": provider,
                                "status_code": 403,
                                "severity": "info",
                                "confidence": 0.85,
                                "evidence": "Bucket exists but is private — check for SSRF or misconfiguration",
                                "suggested_next_step": "Test for SSRF from the target application to access private bucket",
                            })
                except Exception:
                    pass

        tasks = []
        for bucket_name in candidates:
            for provider, url_template in BUCKET_PROVIDERS.items():
                tasks.append(probe(bucket_name, provider, url_template))

        await asyncio.gather(*tasks)
        return findings


# ── Orchestrator ──────────────────────────────────────────────────────────────

class BusinessLogicEngine:
    """Runs all business logic checks."""

    def __init__(self):
        self.race = RaceConditionEngine()
        self.rate_limit = RateLimitBypassEngine()
        self.workflow = WorkflowBypassEngine()
        self.buckets = BucketDiscovery()

    async def scan(self, domain: str, assets: List[Dict]) -> List[Dict]:
        all_findings = []

        # Bucket discovery
        bucket_findings = await self.buckets.discover(domain)
        all_findings.extend(bucket_findings)

        # Workflow bypass on step-like endpoints
        workflow_candidates = self.workflow.find_workflow_candidates(assets)
        wf_tasks = [self.workflow.test_direct_access(a["url"]) for a in workflow_candidates]
        wf_results = await asyncio.gather(*wf_tasks)
        all_findings.extend([r for r in wf_results if r])

        # Rate limit bypass on login-like endpoints
        login_endpoints = [
            a for a in assets
            if any(kw in a.get("url", "").lower() for kw in ["login", "auth", "otp", "2fa", "mfa"])
        ]
        for ep in login_endpoints[:5]:
            rl = await self.rate_limit.test(ep["url"])
            all_findings.extend(rl)

        return all_findings
