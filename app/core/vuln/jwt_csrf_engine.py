"""
Phase 2 - Module 8e: JWT & CSRF Analysis Engine
Tests JWT algorithm confusion, weak secrets, and CSRF protection gaps.
"""
import asyncio
import httpx
import base64
import json
import hmac
import hashlib
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup


# ─── JWT Engine ───────────────────────────────────────────────────────────────

WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "test", "key",
    "jwt", "token", "mysecret", "change_me", "", "null",
    "your-secret-key", "replace-this", "super-secret",
]


class JWTEngine:
    """Tests JWTs for algorithm confusion and weak secret vulnerabilities."""

    def decode_jwt(self, token: str) -> Optional[Dict]:
        """Decode a JWT without verifying the signature."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            # Pad and decode
            header = json.loads(base64.b64decode(parts[0] + "==").decode())
            payload = json.loads(base64.b64decode(parts[1] + "==").decode())
            return {"header": header, "payload": payload, "signature": parts[2], "raw": token}
        except Exception:
            return None

    def forge_none_alg(self, token: str) -> Optional[str]:
        """Forge a JWT with alg=none to bypass signature verification."""
        decoded = self.decode_jwt(token)
        if not decoded:
            return None
        header = decoded["header"].copy()
        header["alg"] = "none"
        new_header = base64.b64encode(json.dumps(header).encode()).decode().rstrip("=")
        orig_payload = token.split(".")[1]
        return f"{new_header}.{orig_payload}."  # Empty signature

    def brute_secret(self, token: str) -> Optional[str]:
        """Try common weak secrets against an HS256 signed JWT."""
        decoded = self.decode_jwt(token)
        if not decoded or decoded["header"].get("alg") not in ["HS256", "HS384", "HS512"]:
            return None

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}"

        for secret in WEAK_SECRETS:
            sig = hmac.new(
                secret.encode(),
                signing_input.encode(),
                hashlib.sha256
            ).digest()
            expected = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            if expected == parts[2]:
                return secret
        return None

    def analyze(self, token: str, source_url: str = "") -> List[Dict]:
        """Comprehensive JWT analysis."""
        findings = []
        decoded = self.decode_jwt(token)
        if not decoded:
            return []

        header = decoded["header"]
        payload = decoded["payload"]

        # Algorithm confusion: alg=none
        none_token = self.forge_none_alg(token)
        if none_token:
            findings.append({
                "type": "JWT: Algorithm Confusion (none)",
                "url": source_url,
                "forged_token": none_token,
                "severity": "critical",
                "confidence": 0.70,
                "suggested_next_step": "Replay forged token in Bearer header to test if server accepts it",
            })

        # Weak secret brute-force
        weak_secret = self.brute_secret(token)
        if weak_secret is not None:
            findings.append({
                "type": "JWT: Weak Secret",
                "url": source_url,
                "secret": weak_secret,
                "severity": "critical",
                "confidence": 0.99,
                "suggested_next_step": f"Forge any payload using secret: '{weak_secret}'",
            })

        # RS256 → HS256 confusion
        if header.get("alg") == "RS256":
            findings.append({
                "type": "JWT: RS256→HS256 Confusion (Potential)",
                "url": source_url,
                "severity": "high",
                "confidence": 0.50,
                "suggested_next_step": "Try signing with public key as HS256 secret",
            })

        # Expired token (still accepted?)
        import time
        if payload.get("exp") and payload["exp"] < time.time():
            findings.append({
                "type": "JWT: Long-lived / Expired Token Found",
                "url": source_url,
                "expiry": payload["exp"],
                "severity": "low",
                "confidence": 0.90,
                "suggested_next_step": "Test if expired token is still accepted by the server",
            })

        return findings


# ─── CSRF Engine ──────────────────────────────────────────────────────────────

class CSRFEngine:
    """Analyzes endpoints for missing CSRF protections."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def test_endpoint(self, url: str, method: str = "POST") -> List[Dict]:
        """Test if an endpoint is vulnerable to CSRF."""
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
            try:
                # Get the form/page first to look for CSRF tokens
                get_resp = await client.get(url)
                soup = BeautifulSoup(get_resp.text, "lxml")
                forms = soup.find_all("form")

                # Check each form
                for form in forms:
                    action = form.get("action", url)
                    form_method = form.get("method", "get").upper()

                    if form_method not in ["POST", "PUT", "DELETE", "PATCH"]:
                        continue

                    inputs = {i.get("name", ""): i.get("value", "") for i in form.find_all("input") if i.get("name")}
                    csrf_present = any(
                        k for k in inputs if any(
                            tok in k.lower()
                            for tok in ["csrf", "token", "_token", "xsrf", "nonce", "authenticity"]
                        )
                    )

                    if not csrf_present:
                        # Check SameSite cookies
                        cookies_str = str(get_resp.headers.get("set-cookie", "")).lower()
                        has_samesite = "samesite=strict" in cookies_str or "samesite=lax" in cookies_str

                        findings.append({
                            "type": "CSRF (Missing Token)" if not has_samesite else "CSRF (No Token, SameSite Present)",
                            "url": url,
                            "form_action": action,
                            "severity": "medium" if has_samesite else "high",
                            "confidence": 0.75,
                            "evidence": "State-changing form found without CSRF token",
                            "suggested_next_step": "Craft a cross-origin HTML page to submit the form and test if action succeeds",
                        })

            except Exception:
                pass
        return findings

    async def scan(self, assets: List[Dict]) -> List[Dict]:
        """Scan all pages for CSRF issues — STRICTLY SEQUENTIAL."""
        # Focus on forms and state-changing endpoints
        candidates = [a for a in assets if a.get("type") in ["page", "endpoint", "api"]
                      and a.get("method", "GET").upper() in ["POST", "PUT", "PATCH", "DELETE"]]
        # Also check all pages (they may have forms)
        pages = [a for a in assets if a.get("type") == "page"]
        all_targets = list({a["url"] for a in candidates + pages})

        findings = []
        for url in all_targets[:50]:  # Cap at 50
            res = await self.test_endpoint(url)
            findings.extend(res)
        return findings
