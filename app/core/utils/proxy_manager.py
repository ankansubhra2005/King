"""
Utility for rotating User-Agents and managing proxies.
"""
import random
from typing import List, Optional

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
]

class ProxyManager:
    def __init__(self, proxies: Optional[List[str]] = None):
        self.proxies = proxies or []

    def get_proxy(self) -> Optional[str]:
        """Return a random proxy from the list if available."""
        if self.proxies:
            return random.choice(self.proxies)
        return None

    @staticmethod
    def get_random_ua() -> str:
        """Return a random modern User-Agent."""
        return random.choice(USER_AGENTS)

    def get_httpx_config(self) -> dict:
        """Return a config dict for httpx.AsyncClient."""
        config = {"headers": {"User-Agent": self.get_random_ua()}}
        proxy = self.get_proxy()
        if proxy:
            config["proxy"] = proxy
        return config
