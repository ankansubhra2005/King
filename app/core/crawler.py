"""
Module 3: Advanced Crawler & Content Discovery
BFS/DFS hybrid crawl with directory brute-forcing and asset extraction.
Multi-tool: katana, gospider, ffuf, feroxbuster — all stream live output.
"""
import asyncio
import httpx
import json as _json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Optional
from app.core.input_layer import ScopeFilter
from app.core.verbose import run_tool_live, v_found, v_probe, v_info
import os

DIR_WORDLIST = os.path.join(os.path.dirname(__file__), "../../wordlists/directory_wordlist.txt")

EXTENSIONS_TO_FUZZ = [
    ".bak", ".old", ".backup", ".sql", ".env",
    ".git", ".svn", ".log", ".conf", ".config",
    ".php", ".asp", ".aspx", ".bak~", ".orig",
]

ASSET_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".json", ".map"}


class Crawler:
    def __init__(
        self,
        scope: Optional[ScopeFilter] = None,
        max_depth: int = 3,
        threads: int = 30,
        timeout: int = 10,
        rate_limit: int = 50,
        custom_wordlist: Optional[str] = None,
    ):
        self.scope = scope
        self.max_depth = max_depth
        self.threads = threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        # Use custom wordlist if provided, else fall back to default
        self.wordlist = custom_wordlist if (custom_wordlist and os.path.exists(custom_wordlist)) else DIR_WORDLIST

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
                            v_probe(url, resp.status_code, asset["type"])

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
        """
        Crawl all live hosts using internal crawler + katana + gospider SEQUENTIALLY.
        """
        all_assets: List[Dict] = []
        seen_urls: Set[str] = set()

        def add_asset(asset: Dict):
            url = asset.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                all_assets.append(asset)

        # 1. Internal BFS crawler
        for host in live_hosts:
            if host.get("is_alive"):
                results = await self.crawl(host["url"])
                for a in results:
                    add_asset(a)

        # 2. Katana
        for host in live_hosts:
            if host.get("is_alive"):
                katana_assets = await self.run_katana(host["url"])
                for a in katana_assets:
                    add_asset(a)

        # 3. Gospider
        for host in live_hosts:
            if host.get("is_alive"):
                gospider_assets = await self.run_gospider(host["url"])
                for a in gospider_assets:
                    add_asset(a)

        return all_assets

    # ── Directory Brute-forcing ────────────────────────────────────────────

    async def bruteforce_dirs(self, base_url: str) -> List[Dict]:
        """Brute-force using internal engine, ffuf, and feroxbuster SEQUENTIALLY."""
        all_assets: List[Dict] = []
        seen: Set[str] = set()

        def add_asset(asset: Dict):
            url = asset.get("url", "")
            if url and url not in seen:
                seen.add(url)
                all_assets.append(asset)

        # 1. Internal
        internal = await self._internal_bruteforce(base_url)
        for a in internal: add_asset(a)

        # 2. ffuf
        ffuf_res = await self.run_ffuf(base_url)
        for a in ffuf_res: add_asset(a)

        # 3. feroxbuster
        ferox_res = await self.run_feroxbuster(base_url)
        for a in ferox_res: add_asset(a)

        return all_assets

    async def _internal_bruteforce(self, base_url: str) -> List[Dict]:
        """Internal BFS directory brute-force from wordlist."""
        if not os.path.exists(self.wordlist):
            return []

        with open(self.wordlist) as f:
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
                                v_probe(url, resp.status_code, f"{len(resp.content)}b")
                                found.append({
                                    "url": url,
                                    "status_code": resp.status_code,
                                    "type": "directory" if path.endswith("/") else "file",
                                    "content_length": len(resp.content),
                                    "source": "king-internal",
                                })
                        except Exception:
                            pass

        await asyncio.gather(*[probe(w) for w in words])
        return found

    # ── Katana (External) ──────────────────────────────────────────────────

    async def run_katana(self, url: str) -> List[Dict]:
        """
        Run Katana for fast JS-aware crawling.
        Install: go install github.com/projectdiscovery/katana/cmd/katana@latest
        """
        cmd = [
            "katana",
            "-u", url,
            "-silent",
            "-jc",          # JS crawling
            "-d", "3",      # depth
            "-nc",          # no color
            "-output", "/dev/stdout",
        ]

        def parse_katana(line: str) -> Optional[str]:
            line = line.strip()
            return line if line.startswith("http") else None

        lines = await run_tool_live("katana", cmd, parse_fn=parse_katana, timeout=120)
        assets = []
        for line in lines:
            v_found("endpoint", line, "katana")
            assets.append({
                "url": line,
                "status_code": 0,
                "type": "js" if line.endswith(".js") else "page",
                "content_type": "",
                "content_length": 0,
                "source": "katana",
            })
        return assets

    # ── Gospider (External) ────────────────────────────────────────────────

    async def run_gospider(self, url: str) -> List[Dict]:
        """
        Run Gospider for web crawling.
        Install: go install github.com/jaeles-project/gospider@latest
        """
        cmd = [
            "gospider",
            "-s", url,
            "-c", "10",     # concurrency
            "-t", "20",     # threads per domain
            "--no-redirect",
            "-q",           # quiet mode (only URLs)
        ]

        def parse_gospider(line: str) -> Optional[str]:
            # gospider output: [url] - [src] https://example.com/path
            if "http" in line:
                parts = line.split(" ")
                for p in parts:
                    if p.startswith("http"):
                        return p.strip()
            return None

        lines = await run_tool_live("gospider", cmd, parse_fn=parse_gospider, timeout=120)
        assets = []
        for line in lines:
            v_found("endpoint", line, "gospider")
            assets.append({
                "url": line,
                "status_code": 0,
                "type": "js" if line.endswith(".js") else "page",
                "content_type": "",
                "content_length": 0,
                "source": "gospider",
            })
        return assets

    # ── ffuf (External) ────────────────────────────────────────────────────

    async def run_ffuf(self, base_url: str) -> List[Dict]:
        """
        Run ffuf for fast directory brute-forcing.
        Install: apt install ffuf  OR  go install github.com/ffuf/ffuf/v2@latest
        """
        wordlist = self.wordlist
        if not os.path.exists(wordlist):
            v_info("ffuf", f"wordlist not found: {wordlist} — skipping")
            return []

        cmd = [
            "ffuf",
            "-u", f"{base_url.rstrip('/')}/FUZZ",
            "-w", wordlist,
            "-mc", "200,201,301,302,403,500",
            "-s",           # silent (just results)
            "-of", "json",
            "-o", "/dev/stdout",
        ]

        collected_json = []

        async def parse_ffuf(line: str) -> Optional[str]:
            try:
                data = _json.loads(line)
                results = data.get("results", [])
                for r in results:
                    collected_json.append(r)
                    return f"{r.get('status')} {r.get('url', '')}"
            except Exception:
                pass
            if '"url"' in line and '"status"' in line:
                return line[:100]
            return None

        lines = await run_tool_live("ffuf", cmd, parse_fn=parse_ffuf, timeout=180)
        assets = []
        for r in collected_json:
            url = r.get("url", "")
            if url:
                v_found("path", url, "ffuf")
                assets.append({
                    "url": url,
                    "status_code": r.get("status", 0),
                    "type": "file",
                    "content_length": r.get("length", 0),
                    "source": "ffuf",
                })
        return assets

    # ── Feroxbuster (External) ─────────────────────────────────────────────

    async def run_feroxbuster(self, base_url: str) -> List[Dict]:
        """
        Run feroxbuster for recursive directory brute-forcing.
        Install: apt install feroxbuster
        """
        wordlist = self.wordlist
        if not os.path.exists(wordlist):
            v_info("feroxbuster", f"wordlist not found: {wordlist} — skipping")
            return []

        cmd = [
            "feroxbuster",
            "--url", base_url,
            "--wordlist", wordlist,
            "--silent",
            "--no-state",
            "--status-codes", "200,201,301,302,403",
            "--output", "/dev/stdout",
        ]

        def parse_ferox(line: str) -> Optional[str]:
            # feroxbuster outputs: STATUS SIZE WORDS LINES URL
            parts = line.split()
            if len(parts) >= 5 and parts[0].isdigit():
                return parts[-1]  # last part is URL
            return None

        lines = await run_tool_live("feroxbuster", cmd, parse_fn=parse_ferox, timeout=180)
        assets = []
        for line in lines:
            if line.startswith("http"):
                v_found("path", line, "feroxbuster")
                assets.append({
                    "url": line,
                    "status_code": 0,
                    "type": "file",
                    "content_length": 0,
                    "source": "feroxbuster",
                })
        return assets

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
            "source": "king-internal",
        }
