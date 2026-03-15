"""
Module 5: Secret Engine
Detects credentials and secrets using regex patterns + Shannon entropy analysis.
"""
import re
import math
import asyncio
import httpx
from typing import List, Dict, Optional


# ── Secret Patterns ────────────────────────────────────────────────────────

SECRET_PATTERNS = {
    # Cloud Providers
    "AWS Access Key":        r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Key":        r"(?i)aws.{0,20}(?:secret|key).{0,5}['\"][0-9a-zA-Z/+]{40}['\"]",
    "GCP API Key":           r"AIza[0-9A-Za-z\-_]{35}",
    "Azure Storage Key":     r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    # Auth Tokens
    "Slack Token":           r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "GitHub Token":          r"gh[opst]_[A-Za-z0-9]{36}",
    "GitHub Classic Token":  r"github_pat_[A-Za-z0-9_]{82}",
    "GitLab Token":          r"glpat-[A-Za-z0-9\-_]{20}",
    "HuggingFace Token":     r"hf_[A-Za-z]{34}",
    "Anthropic Key":         r"sk-ant-[A-Za-z0-9\-]{95}",
    "OpenAI Key":            r"sk-[A-Za-z0-9]{48}",
    "Stripe Secret Key":     r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Publishable":    r"pk_live_[0-9a-zA-Z]{24,}",
    "Twilio Account SID":    r"AC[a-z0-9]{32}",
    "SendGrid API Key":      r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    # JWT
    "JWT Token":             r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}",
    # Private Keys
    "RSA Private Key":       r"-----BEGIN RSA PRIVATE KEY-----",
    "EC Private Key":        r"-----BEGIN EC PRIVATE KEY-----",
    "OpenSSH Private Key":   r"-----BEGIN OPENSSH PRIVATE KEY-----",
    # DB
    "Database URL":          r"(?i)(?:mongodb|postgresql|mysql|redis)://[^\s\"'<>]{5,200}",
    # Generic High-Entropy
    "Generic API Key":       r"""(?i)(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,64})['"]""",
    "Hardcoded Password":    r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'"]{6,64})['"]""",
}

# Strings shorter than MIN_SECRET_LENGTH won't flag entropy check
MIN_SECRET_LENGTH = 16
HIGH_ENTROPY_THRESHOLD = 3.7


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    probs = [f / len(s) for f in freq.values()]
    return -sum(p * math.log2(p) for p in probs)


class SecretEngine:
    def __init__(self):
        self.patterns = {name: re.compile(pattern) for name, pattern in SECRET_PATTERNS.items()}

    # ── Pattern Matching ────────────────────────────────────────────────────

    def scan_text(self, text: str, source_url: str = "") -> List[Dict]:
        """Scan text content for secrets using patterns + entropy."""
        findings = []
        seen = set()

        # Pattern-based
        for name, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                value = match.group(0)[:200]  # cap length
                if value in seen:
                    continue
                seen.add(value)
                entropy = shannon_entropy(value)
                findings.append({
                    "type": name,
                    "value": value,
                    "entropy": round(entropy, 2),
                    "source_url": source_url,
                    "is_high_entropy": entropy >= HIGH_ENTROPY_THRESHOLD,
                    "confidence": self._score_confidence(name, value, entropy),
                })

        # Entropy-only large random strings (generic secrets)
        for token in re.findall(r"[A-Za-z0-9+/=_\-]{20,}", text):
            if token not in seen and shannon_entropy(token) > HIGH_ENTROPY_THRESHOLD + 0.5:
                findings.append({
                    "type": "High Entropy String",
                    "value": token[:200],
                    "entropy": round(shannon_entropy(token), 2),
                    "source_url": source_url,
                    "is_high_entropy": True,
                    "confidence": 0.4,
                })
                seen.add(token)

        return findings

    def _score_confidence(self, name: str, value: str, entropy: float) -> float:
        """Score confidence 0.0-1.0 based on pattern specificity and entropy."""
        base = 0.5
        # High-specific patterns are high-confidence
        specific = ["AWS Access Key", "GitHub Token", "OpenAI Key", "Stripe Secret Key",
                    "RSA Private Key", "JWT Token"]
        if any(s in name for s in specific):
            base = 0.9
        if entropy >= HIGH_ENTROPY_THRESHOLD + 1:
            base = min(base + 0.1, 1.0)
        return round(base, 2)

    # ── Asset Scanning ──────────────────────────────────────────────────────

    async def scan_url(self, url: str) -> List[Dict]:
        """Download URL content and scan for secrets."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                return self.scan_text(resp.text, source_url=url)
        except Exception:
            return []

    async def scan_all(self, assets: List[Dict]) -> List[Dict]:
        """Scan all assets concurrently."""
        sem = asyncio.Semaphore(15)
        all_findings = []

        async def bounded_scan(asset):
            async with sem:
                return await self.scan_url(asset["url"])

        results = await asyncio.gather(*[bounded_scan(a) for a in assets if a.get("url")])
        for r in results:
            all_findings.extend(r)

        # Deduplicate
        seen = set()
        unique = []
        for f in all_findings:
            key = f["type"] + f["value"]
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique
