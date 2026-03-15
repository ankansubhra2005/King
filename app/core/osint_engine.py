"""
Phase 2 - OSINT & External Data Engine
Integrates Shodan, Censys, and GitHub for asset enrichment and leak detection.
"""
import asyncio
import os
import httpx
from typing import List, Dict, Optional
from dotenv import load_dotenv

load_dotenv()


class ShodanClient:
    """Query Shodan for IPs and open services."""

    def __init__(self):
        self.api_key = os.getenv("SHODAN_API_KEY", "")
        self.base_url = "https://api.shodan.io"

    async def host_lookup(self, ip: str) -> Optional[Dict]:
        if not self.api_key:
            return None
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{self.base_url}/shodan/host/{ip}",
                    params={"key": self.api_key}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "ip": ip,
                        "ports": data.get("ports", []),
                        "hostnames": data.get("hostnames", []),
                        "org": data.get("org", ""),
                        "country": data.get("country_name", ""),
                        "vulns": list(data.get("vulns", {}).keys()),
                        "services": [d.get("product", "") for d in data.get("data", []) if d.get("product")],
                        "source": "shodan",
                    }
        except Exception:
            pass
        return None

    async def search_domain(self, domain: str) -> List[Dict]:
        """Search Shodan for all IPs related to a domain."""
        if not self.api_key:
            return []
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    f"{self.base_url}/shodan/host/search",
                    params={"key": self.api_key, "query": f"hostname:{domain}"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return [
                        {
                            "ip": match.get("ip_str"),
                            "ports": [match.get("port")],
                            "product": match.get("product", ""),
                            "source": "shodan",
                        }
                        for match in data.get("matches", [])
                    ]
        except Exception:
            pass
        return []


class GitHubRecon:
    """Search GitHub for secrets and endpoints related to a target domain."""

    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN", "")
        self.base_url = "https://api.github.com/search/code"

    async def search(self, domain: str) -> List[Dict]:
        if not self.token:
            return []

        findings = []
        queries = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
            f'"{domain}" DATABASE_URL',
            f'"{domain}" PRIVATE_KEY',
        ]

        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }

        async with httpx.AsyncClient(timeout=15) as client:
            for query in queries:
                try:
                    resp = await client.get(
                        self.base_url,
                        params={"q": query, "per_page": 10},
                        headers=headers,
                    )
                    if resp.status_code == 200:
                        items = resp.json().get("items", [])
                        for item in items:
                            findings.append({
                                "type": "GitHub Leak",
                                "query": query,
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "file": item.get("name", ""),
                                "url": item.get("html_url", ""),
                                "severity": "high",
                                "confidence": 0.70,
                                "suggested_next_step": f"Inspect {item.get('html_url')} for exposed credentials",
                            })
                    await asyncio.sleep(1.5)  # GitHub rate limit
                except Exception:
                    pass
        return findings


class OSINTEngine:
    def __init__(self):
        self.shodan = ShodanClient()
        self.github = GitHubRecon()

    async def enrich_subdomains(self, subdomains: List[Dict]) -> List[Dict]:
        """Enrich alive subdomains with Shodan IP data."""
        enriched = []
        tasks = []
        for sub in subdomains:
            ip = sub.get("ip_address")
            if ip:
                tasks.append(self.shodan.host_lookup(ip))
            else:
                tasks.append(asyncio.sleep(0))  # placeholder

        results = await asyncio.gather(*tasks)
        for sub, shodan_data in zip(subdomains, results):
            if shodan_data:
                sub["shodan"] = shodan_data
                # Flag interesting ports
                risky_ports = [21, 22, 23, 25, 445, 1433, 3306, 5432, 6379, 27017, 8080, 8443]
                sub["exposed_ports"] = [p for p in shodan_data.get("ports", []) if p in risky_ports]
                if sub.get("exposed_ports"):
                    sub["risk_note"] = f"Exposed risky ports: {sub['exposed_ports']}"
            enriched.append(sub)
        return enriched

    async def scan(self, domain: str, subdomains: List[Dict]) -> Dict:
        """Run all OSINT modules and return combined results."""
        enriched = await self.enrich_subdomains(subdomains)
        gh_findings = await self.github.search(domain)
        shodan_domain = await self.shodan.search_domain(domain)

        return {
            "enriched_subdomains": enriched,
            "github_leaks": gh_findings,
            "shodan_assets": shodan_domain,
        }
