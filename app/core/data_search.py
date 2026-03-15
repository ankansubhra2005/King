"""
Internet-Wide Sensitive Data Search Engine
Searches GitHub (deep), Google Dorks, and cloud buckets for leaked data.
"""
import asyncio
import os
import httpx
import re
from typing import List, Dict, Optional
from dotenv import load_dotenv

load_dotenv()


# ── Google Dork Templates ─────────────────────────────────────────────────────

DORK_TEMPLATES = [
    'site:{domain} filetype:env',
    'site:{domain} filetype:sql',
    'site:{domain} filetype:log',
    'site:{domain} filetype:bak',
    'site:{domain} inurl:config password',
    'site:{domain} inurl:admin',
    'site:{domain} inurl:dashboard',
    'site:{domain} inurl:api/v1',
    'site:{domain} inurl:swagger',
    'site:{domain} "api_key"',
    'site:{domain} "access_token"',
    'site:{domain} "private_key"',
    'site:{domain} "password"',
    'site:{domain} "SECRET_KEY"',
    'site:{domain} ext:php inurl:?id=',
]


class GoogleDorkEngine:
    """
    Uses SerpAPI or similar search API to execute Google dorks programmatically.
    NOTE: Requires SERP_API_KEY in .env — falls back to printing dork list.
    """

    def __init__(self):
        self.api_key = os.getenv("SERP_API_KEY", "")

    async def run(self, domain: str) -> List[Dict]:
        dorks = [t.replace("{domain}", domain) for t in DORK_TEMPLATES]

        if not self.api_key:
            # No API key — return the dork list as actionable findings for manual execution
            return [
                {
                    "type": "Google Dork (Manual)",
                    "query": dork,
                    "severity": "info",
                    "confidence": 1.0,
                    "suggested_next_step": f"Run in browser: https://www.google.com/search?q={dork.replace(' ', '+')}",
                }
                for dork in dorks
            ]

        results = []
        async with httpx.AsyncClient(timeout=15) as client:
            for dork in dorks[:5]:   # Limit to 5 to avoid rate limits
                try:
                    resp = await client.get(
                        "https://serpapi.com/search.json",
                        params={"q": dork, "api_key": self.api_key, "num": 10}
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        for item in data.get("organic_results", []):
                            results.append({
                                "type": "Google Dork Hit",
                                "dork_query": dork,
                                "url": item.get("link", ""),
                                "title": item.get("title", ""),
                                "snippet": item.get("snippet", "")[:200],
                                "severity": "medium",
                                "confidence": 0.75,
                                "suggested_next_step": "Visit link and check for exposed sensitive data",
                            })
                    await asyncio.sleep(1.0)  # Rate limit
                except Exception:
                    pass
        return results


# ── GitHub Deep Search ────────────────────────────────────────────────────────

GITHUB_QUERIES = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret_key',
    '"{domain}" access_token',
    '"{domain}" DATABASE_URL',
    '"{domain}" PRIVATE_KEY',
    '"{domain}" aws_access_key',
    '"{domain}" "BEGIN RSA PRIVATE KEY"',
    'org:{org} password',
    'org:{org} secret NOT example',
    'org:{org} api_key NOT example',
    'org:{org} DATABASE_URL NOT example',
]

class GitHubDeepSearch:
    """Searches GitHub code and commits for sensitive data related to the target."""

    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN", "")

    async def search_code(self, domain: str, org: Optional[str] = None) -> List[Dict]:
        if not self.token:
            return []

        findings = []
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }

        # Guess org name from domain
        org_name = org or domain.split(".")[0]
        queries = [
            q.replace("{domain}", domain).replace("{org}", org_name)
            for q in GITHUB_QUERIES
        ]

        async with httpx.AsyncClient(timeout=20) as client:
            for query in queries:
                try:
                    resp = await client.get(
                        "https://api.github.com/search/code",
                        params={"q": query, "per_page": 5},
                        headers=headers,
                    )
                    if resp.status_code == 200:
                        for item in resp.json().get("items", []):
                            findings.append({
                                "type": "GitHub Code Leak",
                                "query": query,
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "file": item.get("name", ""),
                                "url": item.get("html_url", ""),
                                "severity": "high",
                                "confidence": 0.72,
                                "suggested_next_step": f"Inspect {item.get('html_url')} for exposed credentials and secrets",
                            })
                    elif resp.status_code == 403:
                        await asyncio.sleep(5)  # Secondary rate limit
                    await asyncio.sleep(2)  # GitHub rate limit
                except Exception:
                    pass

        return findings

    async def search_commits(self, domain: str) -> List[Dict]:
        """Search for accidentally committed secrets in repo history."""
        if not self.token:
            return []
        findings = []
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.cloak-preview+json",  # Commit search preview
        }
        org_name = domain.split(".")[0]

        async with httpx.AsyncClient(timeout=15) as client:
            for query in [f'"{domain}" secret', f'org:{org_name} removed password']:
                try:
                    resp = await client.get(
                        "https://api.github.com/search/commits",
                        params={"q": query, "per_page": 5},
                        headers=headers,
                    )
                    if resp.status_code == 200:
                        for item in resp.json().get("items", []):
                            findings.append({
                                "type": "GitHub Commit Leak",
                                "query": query,
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "commit_message": item.get("commit", {}).get("message", "")[:100],
                                "url": item.get("html_url", ""),
                                "severity": "high",
                                "confidence": 0.65,
                                "suggested_next_step": "Check commit diff for accidentally committed secrets that were later removed",
                            })
                    await asyncio.sleep(2)
                except Exception:
                    pass
        return findings



# ── Hunter.io Email Recon ─────────────────────────────────────────────────────

class EmailReconEngine:
    """
    Phase 2 - Hunter.io / Email Recon.
    Harvests employee emails, names, and job titles via the Hunter.io API.
    Requires HUNTER_IO_API_KEY in .env.
    API docs: https://hunter.io/api-documentation/v2
    """

    HUNTER_BASE = "https://api.hunter.io/v2"

    def __init__(self):
        self.api_key = os.getenv("HUNTER_IO_API_KEY", "")

    async def domain_search(self, domain: str, limit: int = 100) -> List[Dict]:
        """Retrieve all publicly known emails and employee info for a domain."""
        if not self.api_key:
            return [
                {
                    "type": "Email Recon (Manual)",
                    "url": f"https://hunter.io/search/{domain}",
                    "severity": "info",
                    "confidence": 1.0,
                    "suggested_next_step": (
                        f"Visit https://hunter.io/search/{domain} or set HUNTER_IO_API_KEY in .env "
                        "to enable automated email harvesting"
                    ),
                }
            ]

        findings: List[Dict] = []
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    f"{self.HUNTER_BASE}/domain-search",
                    params={
                        "domain": domain,
                        "limit": limit,
                        "api_key": self.api_key,
                    },
                )
                if resp.status_code != 200:
                    return []

                data = resp.json().get("data", {})
                org = data.get("organization", "")
                pattern = data.get("pattern", "")

                for person in data.get("emails", []):
                    email = person.get("value", "")
                    confidence = person.get("confidence", 0) / 100
                    first = person.get("first_name", "")
                    last = person.get("last_name", "")
                    position = person.get("position", "N/A")
                    sources = [s.get("uri", "") for s in person.get("sources", [])]

                    severity = "medium" if position and any(
                        kw in position.lower()
                        for kw in ["engineer", "developer", "admin", "security", "devops", "architect", "cto", "ciso"]
                    ) else "info"

                    findings.append({
                        "type": "Employee Email",
                        "email": email,
                        "full_name": f"{first} {last}".strip(),
                        "position": position,
                        "organization": org,
                        "email_pattern": pattern,
                        "confidence": confidence,
                        "severity": severity,
                        "sources": sources[:3],
                        "suggested_next_step": (
                            "Add to phishing assessment wordlist and LinkedIn correlation. "
                            "High-value targets: engineers with production access."
                        ),
                    })

                # Also surface the email format pattern as a finding
                if pattern:
                    findings.append({
                        "type": "Email Format Pattern",
                        "pattern": pattern,
                        "organization": org,
                        "severity": "info",
                        "confidence": 0.95,
                        "suggested_next_step": (
                            f"Use pattern '{pattern}@{domain}' to construct email addresses "
                            "for unenumerated employees found via LinkedIn OSINT"
                        ),
                    })

        except Exception as exc:
            log.debug("Hunter.io error: %s", exc)

        return findings

    async def verify_email(self, email: str) -> Optional[Dict]:
        """Verify if a specific email address exists using Hunter.io's verifier."""
        if not self.api_key:
            return None
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{self.HUNTER_BASE}/email-verifier",
                    params={"email": email, "api_key": self.api_key},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    return {
                        "email": email,
                        "status": data.get("status"),   # valid / risky / disposable / invalid
                        "score": data.get("score", 0),
                        "is_deliverable": data.get("result") == "deliverable",
                    }
        except Exception:
            pass
        return None


# ── Main Engine ───────────────────────────────────────────────────────────────

class DataSearchEngine:
    """Orchestrates all internet-wide sensitive data search modules."""

    def __init__(self):
        self.dorks = GoogleDorkEngine()
        self.github = GitHubDeepSearch()
        self.email_recon = EmailReconEngine()

    async def scan(self, domain: str, org: Optional[str] = None) -> List[Dict]:
        """Run all search modules concurrently."""
        results = await asyncio.gather(
            self.dorks.run(domain),
            self.github.search_code(domain, org),
            self.github.search_commits(domain),
            self.email_recon.domain_search(domain),
        )
        all_findings = []
        for r in results:
            all_findings.extend(r)
        return all_findings
