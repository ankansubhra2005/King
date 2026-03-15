"""
Module 3: Advanced Crawler & Content Discovery
BFS/DFS hybrid crawl with directory brute-forcing and asset extraction.
"""
import asyncio
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Optional
from app.core.input_layer import ScopeFilter
import os

DIR_WORDLIST = os.path.join(os.path.dirname(__file__), "../../wordlists/directory_wordlist.txt")

EXTENSIONS_TO_FUZZ = [
    ".bak", ".old", ".backup", ".sql", ".env",
    ".git", ".svn", ".log", ".conf", ".config",
    ".php", ".asp", ".aspx", ".bak~", ".orig",
]

ASSET_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".json", ".map"}


class Crawler:
    def __init__(self, scope: Optional[ScopeFilter] = None, max_depth: int = 3,
                 threads: int = 30, timeout: int = 10, rate_limit: int = 50):
        self.scope = scope
        self.max_depth = max_depth
        self.threads = threads
        self.timeout = timeout
        self.rate_limit = rate_limit

    # ── Core Crawler ───────────────────────────────────────────────────────

    async def crawl(self, base_url: str) -> List[Dict]:
        """Run BFS crawl from base_url, returning all discovered assets."""
        visited: Set[str] = set()
        queue = [(base_url, 0)]
        assets = []
        sem = asyncio.Semaphore(self.threads)

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=self.timeout) as client:
            while queue:
                batch = queue[:self.threads]
                queue = queue[self.threads:]

                async def fetch(url: str, depth: int):
                    if url in visited or depth > self.max_depth:
                        return
                    # Scope check
                    if self.scope and not self.scope.is_in_scope(urlparse(url).netloc):
                        return
                    visited.add(url)
                    async with sem:
                        try:
                            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                            asset = self._classify_asset(url, resp)
                            assets.append(asset)

                            # Parse HTML for new links
                            if "text/html" in resp.headers.get("content-type", ""):
                                links = self._extract_links(resp.text, url)
                                for link in links:
                                    if link not in visited:
                                        queue.append((link, depth + 1))
                        except Exception:
                            pass

                await asyncio.gather(*[fetch(url, depth) for url, depth in batch])

        return assets

    async def crawl_all(self, live_hosts: List[Dict]) -> List[Dict]:
        """Crawl all live hosts in parallel."""
        all_assets = []
        tasks = []
        for host in live_hosts:
            if host.get("is_alive"):
                tasks.append(self.crawl(host["url"]))
        results = await asyncio.gather(*tasks)
        for r in results:
            all_assets.extend(r)
        return all_assets

    # ── Directory Brute-forcing ────────────────────────────────────────────

    async def bruteforce_dirs(self, base_url: str) -> List[Dict]:
        """Brute-force directories and files on a target."""
        if not os.path.exists(DIR_WORDLIST):
            return []

        with open(DIR_WORDLIST) as f:
            words = [w.strip() for w in f if w.strip()]

        sem = asyncio.Semaphore(self.threads)
        found = []

        async def probe(word: str):
            async with sem:
                async with httpx.AsyncClient(verify=False, timeout=8) as client:
                    paths_to_try = [f"/{word}", f"/{word}/"]
                    # Extension fuzzing
                    paths_to_try += [f"/{word}{ext}" for ext in EXTENSIONS_TO_FUZZ]

                    for path in paths_to_try:
                        try:
                            url = base_url.rstrip("/") + path
                            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                            if resp.status_code not in [404, 429, 503]:
                                found.append({
                                    "url": url,
                                    "status_code": resp.status_code,
                                    "type": "directory" if path.endswith("/") else "file",
                                    "content_length": len(resp.content),
                                })
                        except Exception:
                            pass

        await asyncio.gather(*[probe(w) for w in words])
        return found

    # ── Helpers ────────────────────────────────────────────────────────────

    def _extract_links(self, html: str, base: str) -> List[str]:
        soup = BeautifulSoup(html, "lxml")
        links = set()
        for tag in soup.find_all(["a", "link", "script", "form", "iframe"]):
            for attr in ["href", "src", "action"]:
                val = tag.get(attr)
                if val:
                    full = urljoin(base, val)
                    parsed = urlparse(full)
                    if parsed.scheme in ["http", "https"]:
                        links.add(full)
        return list(links)

    def _classify_asset(self, url: str, resp) -> Dict:
        ext = os.path.splitext(urlparse(url).path)[1].lower()
        content_type = resp.headers.get("content-type", "")
        asset_type = "page"
        if ext in ASSET_EXTENSIONS or "javascript" in content_type:
            asset_type = "js"
        elif ext == ".json" or "application/json" in content_type:
            asset_type = "api"
        elif "graphql" in url.lower():
            asset_type = "graphql"
        elif ext in [".png", ".jpg", ".gif", ".svg", ".ico", ".woff"]:
            asset_type = "static"
        return {
            "url": url,
            "status_code": resp.status_code,
            "type": asset_type,
            "content_type": content_type,
            "content_length": len(resp.content),
        }
