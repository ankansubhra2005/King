"""
Phase 2 - Module 8d: IDOR / Mass Assignment Engine
Tests for Insecure Direct Object References and mass-assignment vulnerabilities.
"""
import asyncio
import httpx
import re
import json
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs


# Numeric ID patterns — these are IDOR candidates
ID_PATTERNS = [
    r"/(\d+)(?:/|$|\?)",        # /users/123  or  /orders/456/
    r"[?&]id=(\d+)",            # ?id=123
    r"[?&]user_id=(\d+)",
    r"[?&]account_id=(\d+)",
    r"[?&]order_id=(\d+)",
    r"[?&]invoice_id=(\d+)",
    r"[?&]doc_id=(\d+)",
]

# Fields commonly exposing mass assignment vulnerabilities
MASS_ASSIGN_FIELDS = [
    "admin", "is_admin", "role", "is_superuser", "is_staff",
    "privilege", "level", "permissions", "group", "verified",
    "email_verified", "account_type", "plan", "subscription",
    "balance", "credits", "price", "discount",
]


class IDOREngine:
    def __init__(self, session_tokens: Optional[List[str]] = None, timeout: int = 10):
        """
        session_tokens: list of cookies/tokens for DIFFERENT user accounts.
        If provided, enables cross-account IDOR testing.
        """
        self.session_tokens = session_tokens or []
        self.timeout = timeout

    # ── IDOR Detection ─────────────────────────────────────────────────────

    def find_idor_candidates(self, assets: List[Dict]) -> List[Dict]:
        """Identify URLs that contain numeric IDs (IDOR candidates)."""
        candidates = []
        for asset in assets:
            url = asset.get("url", "")
            for pattern in ID_PATTERNS:
                match = re.search(pattern, url)
                if match:
                    candidates.append({
                        "url": url,
                        "id_value": match.group(1),
                        "pattern": pattern,
                    })
                    break
        return candidates

    async def test_idor(self, candidate: Dict) -> List[Dict]:
        """Test IDOR by incrementing/decrementing the ID."""
        findings = []
        url = candidate["url"]
        orig_id = int(candidate["id_value"])

        test_ids = [orig_id - 1, orig_id + 1, orig_id - 100, 1, 2, 3, 9999]

        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
            # Get baseline response
            try:
                base_resp = await client.get(url)
                if base_resp.status_code in [401, 403, 404]:
                    return []
                base_len = len(base_resp.content)
            except Exception:
                return []

            for test_id in test_ids:
                test_url = url.replace(str(orig_id), str(test_id))
                if test_url == url:
                    continue
                try:
                    resp = await client.get(test_url)
                    if resp.status_code == 200 and len(resp.content) > 100:
                        # Different content = potentially accessing another user's data
                        if abs(len(resp.content) - base_len) > 50:
                            findings.append({
                                "type": "IDOR (Potential)",
                                "original_url": url,
                                "test_url": test_url,
                                "original_id": orig_id,
                                "tested_id": test_id,
                                "status_code": resp.status_code,
                                "severity": "high",
                                "confidence": 0.65,
                                "evidence": f"Different response size ({len(resp.content)} vs {base_len}) for id={test_id}",
                                "suggested_next_step": "Compare responses manually — check for PII or sensitive data",
                            })
                except Exception:
                    pass

        return findings

    # ── Mass Assignment ─────────────────────────────────────────────────────

    async def test_mass_assignment(self, url: str, method: str = "POST") -> List[Dict]:
        """Inject privileged fields into request body to test mass assignment."""
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
            for field in MASS_ASSIGN_FIELDS:
                payloads = [
                    {field: True},
                    {field: 1},
                    {field: "admin"},
                    {field: "superuser"},
                ]
                for payload in payloads:
                    try:
                        resp = await client.request(
                            method, url,
                            json=payload,
                            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
                        )
                        resp_lower = resp.text.lower()
                        # Response confirms the field was accepted
                        if (resp.status_code in [200, 201, 204] and
                                (field in resp_lower or "success" in resp_lower or "updated" in resp_lower)):
                            findings.append({
                                "type": "Mass Assignment (Potential)",
                                "url": url,
                                "field": field,
                                "payload": payload,
                                "status_code": resp.status_code,
                                "severity": "high",
                                "confidence": 0.60,
                                "evidence": f"Server returned {resp.status_code} with field '{field}' echoed in response",
                                "suggested_next_step": "Verify privilege escalation by re-fetching user profile",
                            })
                            break
                    except Exception:
                        pass
        return findings

    async def scan(self, assets: List[Dict]) -> List[Dict]:
        """Full IDOR and mass-assignment scan."""
        findings = []

        # IDOR
        candidates = self.find_idor_candidates(assets)
        idor_tasks = [self.test_idor(c) for c in candidates]
        idor_results = await asyncio.gather(*idor_tasks)
        for r in idor_results:
            findings.extend(r)

        # Mass Assignment — API endpoints only
        api_assets = [a for a in assets if a.get("type") in ["api", "graphql", "endpoint"]]
        ma_tasks = [self.test_mass_assignment(a["url"], a.get("method", "POST")) for a in api_assets]
        ma_results = await asyncio.gather(*ma_tasks)
        for r in ma_results:
            findings.extend(r)

        return findings
