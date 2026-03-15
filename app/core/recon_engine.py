"""
Module 2: Recon Engine
Handles subdomain enumeration (passive + active) and live host detection.
"""
import asyncio
import subprocess
import json
import dns.resolver
import dns.exception
import httpx
from typing import List, Dict, Optional, AsyncGenerator
from app.core.input_layer import ScopeFilter
from app.core.utils.deduplicator import Deduplicator
from itertools import product
import os
import logging
from app.core.verbose import v_found, v_info, v_probe, v_tool, v_section

log = logging.getLogger(__name__)


WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "../../wordlists/subdomain_wordlist.txt")


class ReconEngine:
    def __init__(self, domain: str, scope: Optional[ScopeFilter] = None, threads: int = 50):
        self.domain = domain
        self.scope = scope
        self.threads = threads
        self.found: set = set()

    # ── 1. Passive Enumeration ──────────────────────────────────────────────

    async def passive_subfinder(self) -> List[str]:
        """Run subfinder (must be installed on system)."""
        v_tool("subfinder", f"-d {self.domain} -silent -json")
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.domain, "-silent", "-json"],
                capture_output=True, text=True, timeout=120
            )
            found = []
            for line in result.stdout.splitlines():
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    if host:
                        v_found("subdomain", host, "subfinder")
                        found.append(host)
                except json.JSONDecodeError:
                    h = line.strip()
                    if h:
                        v_found("subdomain", h, "subfinder")
                        found.append(h)
            return [f for f in found if f]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            v_info("subfinder", "not installed or timed out — skipping")
            return []

    async def passive_crt_sh(self) -> List[str]:
        """Certificate transparency lookup via crt.sh."""
        v_info("crt.sh", f"querying for %.{self.domain}")
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url)
                data = resp.json()
                names = set()
                for entry in data:
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(self.domain):
                            names.add(name)
                for n in names:
                    v_found("subdomain", n, "crt.sh")
                return list(names)
        except Exception:
            v_info("crt.sh", "request failed — skipping")
            return []

    async def run_amass(self) -> List[str]:
        """Run OWASP Amass (must be installed)."""
        v_tool("amass", f"enum -passive -d {self.domain} -silent")
        try:
            result = subprocess.run(
                ["amass", "enum", "-passive", "-d", self.domain, "-silent"],
                capture_output=True, text=True, timeout=300
            )
            found = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            for f in found:
                v_found("subdomain", f, "amass")
            return found
        except (FileNotFoundError, subprocess.TimeoutExpired):
            v_info("amass", "not installed or timed out — skipping")
            return []

    async def run_theharvester(self) -> List[str]:
        """Run theHarvester for emails and subdomains."""
        try:
            # -b all: uses all sources, -d domain, -l limit
            result = subprocess.run(
                ["theHarvester", "-d", self.domain, "-b", "all", "-l", "100"],
                capture_output=True, text=True, timeout=180
            )
            # Basic parsing as theHarvester output is messy
            found = []
            for line in result.stdout.splitlines():
                if self.domain in line and "." in line:
                    # simplistic extraction
                    parts = line.split()
                    for p in parts:
                        if p.endswith(self.domain) and "@" not in p:
                            found.append(p.strip().rstrip(":"))
            return found
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    async def run_historical_endpoints(self) -> Dict[str, List]:
        """Run gau or waybackurls to find historical subdomains/endpoints."""
        tools = [["gau", self.domain], ["waybackurls", self.domain]]
        all_subs = set()
        all_assets = []
        seen_urls = set()

        for cmd in tools:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line: continue
                    
                    # Deduplicate URLs
                    if line in seen_urls: continue
                    seen_urls.add(line)
                    
                    # Extract subdomain from URL
                    try:
                        u = line.split("?")[0] # remove query
                        host = u.split("//")[-1].split("/")[0]
                        if host.endswith(self.domain):
                            all_subs.add(host)
                            
                        # Add as asset if it looks like a valid URL or important file
                        ext = line.split("?")[0].split(".")[-1].lower()
                        asset_type = "js" if ext == "js" else "url"
                        all_assets.append({
                            "url": line,
                            "type": asset_type,
                            "source": "historical"
                        })
                    except Exception:
                        continue
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return {"subdomains": list(all_subs), "assets": all_assets}

    # ── 2. Active Enumeration ──────────────────────────────────────────────

    async def active_bruteforce(self) -> List[str]:
        """DNS brute-force from wordlist."""
        if not os.path.exists(WORDLIST_PATH):
            return []

        with open(WORDLIST_PATH) as f:
            words = [w.strip() for w in f if w.strip()]

        sem = asyncio.Semaphore(self.threads)
        found = []

        async def resolve(word):
            fqdn = f"{word}.{self.domain}"
            async with sem:
                try:
                    answers = dns.resolver.resolve(fqdn, "A")
                    if answers:
                        found.append(fqdn)
                except (dns.exception.DNSException, Exception):
                    pass

        await asyncio.gather(*[resolve(w) for w in words])
        return found

    def generate_permutations(self, subdomains: List[str]) -> List[str]:
        """Generate alterations and permutations of known subdomains."""
        prefixes = ["dev", "staging", "test", "admin", "api", "v1", "v2", "old", "new", "beta"]
        perms = set()
        for sub in subdomains:
            label = sub.split(".")[0]
            for p in prefixes:
                perms.add(f"{p}-{label}.{self.domain}")
                perms.add(f"{label}-{p}.{self.domain}")
                perms.add(f"{p}.{label}.{self.domain}")
        return list(perms)

    async def check_zone_transfer(self) -> List[str]:
        """Attempt AXFR zone transfer — misconfigured DNS vulnerability."""
        results = []
        try:
            ns_answers = dns.resolver.resolve(self.domain, "NS")
            for ns in ns_answers:
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(str(ns.target), self.domain))
                    for name in z.nodes.keys():
                        fqdn = f"{name}.{self.domain}"
                        results.append(fqdn)
                except Exception:
                    pass
        except Exception:
            pass
        return results

    # ── 3. Origin IP Discovery ──────────────────────────────────────────────

    async def find_origin_ip(self) -> Optional[str]:
        """
        Attempt to find the real origin IP behind a CDN/WAF.
        Strategies:
        - Historical DNS lookup (placeholder for SecurityTrails API integration).
        - Subdomains that don't use WAF (e.g., mail., direct., origin.).
        """
        bypass_prefixes = ["direct", "origin", "mail", "smtp", "cpanel", "ftp", "ssh", "git"]
        for prefix in bypass_prefixes:
            fqdn = f"{prefix}.{self.domain}"
            try:
                answers = dns.resolver.resolve(fqdn, "A")
                for rdata in answers:
                    return str(rdata)
            except Exception:
                pass
        return None

    # ── 4. Live Host Detection ──────────────────────────────────────────────

    async def probe_live(self, subdomains: List[str]) -> List[Dict]:
        """Check which subdomains are alive via HTTP/HTTPS."""
        sem = asyncio.Semaphore(30)
        results = []

        async def probe(fqdn):
            async with sem:
                for scheme in ["https", "http"]:
                    url = f"{scheme}://{fqdn}"
                    try:
                        async with httpx.AsyncClient(
                            verify=False, follow_redirects=True, timeout=8
                        ) as client:
                            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                            server = resp.headers.get("Server", "")
                            cdn = self._detect_cdn(resp.headers)
                            waf = self._detect_waf(resp.headers)
                            title = self._extract_title(resp.text)
                            results.append({
                                "fqdn": fqdn,
                                "url": url,
                                "status_code": resp.status_code,
                                "server": server,
                                "cdn_detected": cdn is not None,
                                "cdn_name": cdn,
                                "waf_detected": waf,
                                "title": title,
                                "is_alive": True,
                            })
                            return
                    except Exception:
                        pass
                results.append({"fqdn": fqdn, "is_alive": False})

        await asyncio.gather(*[probe(s) for s in subdomains])
        return results

    def _detect_cdn(self, headers) -> Optional[str]:
        cdn_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare"],
            "Akamai": ["x-akamai-transformed", "akamai"],
            "Fastly": ["x-served-by", "fastly"],
            "CloudFront": ["x-amz-cf-id", "cloudfront"],
        }
        h_str = str(headers).lower()
        for name, sigs in cdn_signatures.items():
            if any(s in h_str for s in sigs):
                return name
        return None

    def _detect_waf(self, headers) -> Optional[str]:
        waf_signatures = {
            "Cloudflare WAF": ["cf-ray"],
            "AWS WAF": ["x-amzn-requestid"],
            "Imperva": ["x-iinfo"],
        }
        h_str = str(headers).lower()
        for name, sigs in waf_signatures.items():
            if any(s in h_str for s in sigs):
                return name
        return None

    def _extract_title(self, html: str) -> Optional[str]:
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip()[:200] if match else None

    # ── Main Entry Point ────────────────────────────────────────────────────

    async def enumerate(self, passive_only: bool = False) -> List[Dict]:
        """Run all enumeration steps and return enriched live-host data."""
        # Passive
        passive_tasks = {
            "subfinder": self.passive_subfinder(),
            "crt_sh": self.passive_crt_sh(),
            "amass": self.run_amass(),
            "theharvester": self.run_theharvester(),
            # historical returns a dict
        }
        
        # Run historical separately to handle its unique return format
        historical_future = self.run_historical_endpoints()
        results = await asyncio.gather(*passive_tasks.values())
        hist_data = await historical_future
        
        source_map = {} # fqdn -> set of sources
        passive_assets = hist_data.get("assets", [])
        
        # Process historical subdomains
        for fqdn in hist_data.get("subdomains", []):
            if fqdn:
                if fqdn not in source_map: source_map[fqdn] = set()
                source_map[fqdn].add("passive:historical")

        for name, found in zip(passive_tasks.keys(), results):
            for fqdn in found:
                fqdn = fqdn.strip().lower().lstrip("*.")
                if fqdn:
                    if fqdn not in source_map: source_map[fqdn] = set()
                    source_map[fqdn].add(f"passive:{name}")

        if not passive_only:
            # Active
            brute = await self.active_bruteforce()
            for fqdn in brute:
                fqdn = fqdn.strip().lower().lstrip("*.")
                if fqdn:
                    if fqdn not in source_map: source_map[fqdn] = set()
                    source_map[fqdn].add("active:bruteforce")

            # Zone Transfer
            zt = await self.check_zone_transfer()
            for fqdn in zt:
                fqdn = fqdn.strip().lower().lstrip("*.")
                if fqdn:
                    if fqdn not in source_map: source_map[fqdn] = set()
                    source_map[fqdn].add("active:zone_transfer")

            # Permutations
            perms = self.generate_permutations(list(source_map.keys()))
            for fqdn in perms:
                fqdn = fqdn.strip().lower().lstrip("*.")
                if fqdn:
                    if fqdn not in source_map: source_map[fqdn] = set()
                    source_map[fqdn].add("active:permutation")

        # Deduplicate and Filter
        clean_subs = list(source_map.keys())
        
        # Scope filter
        if self.scope:
            clean_subs = self.scope.filter(clean_subs)

        # Live host probe
        live = await self.probe_live(clean_subs)
        
        # Enrich with source info
        for s in live:
            fqdn = s.get("fqdn")
            if fqdn in source_map:
                s["sources"] = list(source_map[fqdn])
        
        return {"subdomains": live, "assets": passive_assets}


# ── CertStream Live Monitor ────────────────────────────────────────────────────

class CertStreamMonitor:
    """
    Phase 1 - CertStream Live Monitor.
    Connects to the Certificate Transparency Log stream and emits new subdomains
    for the target domain in real-time as SSL/TLS certificates are issued.

    Requires: pip install websockets
    Source:   wss://certstream.calidog.io/
    """
    CERTSTREAM_URL = "wss://certstream.calidog.io/"

    def __init__(self, domain: str):
        self.domain = domain.lower().lstrip("*.")

    async def stream(self, timeout: int = 300) -> AsyncGenerator[Dict, None]:
        """
        Async generator that yields subdomain findings as they appear on the CTL stream.
        Runs until `timeout` seconds have elapsed or the caller breaks.

        Usage:
            async for finding in CertStreamMonitor("example.com").stream(timeout=60):
                print(finding)
        """
        try:
            import websockets  # optional dep
        except ImportError:
            log.warning("websockets package not installed — falling back to crt.sh polling.")
            async for finding in self._poll_crt_sh():
                yield finding
            return

        deadline = asyncio.get_event_loop().time() + timeout
        seen: set = set()

        try:
            async with websockets.connect(
                self.CERTSTREAM_URL,
                ping_interval=20,
                ping_timeout=10,
                close_timeout=5,
            ) as ws:
                while asyncio.get_event_loop().time() < deadline:
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=10)
                        data = json.loads(raw)
                    except (asyncio.TimeoutError, json.JSONDecodeError):
                        continue
                    except Exception as exc:
                        log.debug("CertStream recv error: %s", exc)
                        break

                    msg_type = data.get("message_type", "")
                    if msg_type != "certificate_update":
                        continue

                    leaf = data.get("data", {}).get("leaf_cert", {})
                    all_domains = leaf.get("all_domains", [])

                    for name in all_domains:
                        name = name.lower().lstrip("*.")
                        if name.endswith(f".{self.domain}") or name == self.domain:
                            if name not in seen:
                                seen.add(name)
                                yield {
                                    "type": "CertStream Subdomain",
                                    "fqdn": name,
                                    "issuer": leaf.get("issuer", {}).get("O", ""),
                                    "not_before": leaf.get("not_before"),
                                    "source": "certstream",
                                    "severity": "info",
                                    "confidence": 0.95,
                                    "evidence": "Certificate issued and detected on CT log in real-time",
                                }
        except Exception as exc:
            log.warning("CertStream connection failed: %s. Falling back to crt.sh.", exc)
            async for finding in self._poll_crt_sh():
                yield finding

    async def _poll_crt_sh(self) -> AsyncGenerator[Dict, None]:
        """Fallback: poll crt.sh once and yield results."""
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url)
                seen: set = set()
                for entry in resp.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(self.domain) and name not in seen:
                            seen.add(name)
                            yield {
                                "type": "CertStream Subdomain (crt.sh fallback)",
                                "fqdn": name,
                                "not_before": entry.get("not_before"),
                                "source": "crt.sh_poll",
                                "severity": "info",
                                "confidence": 0.90,
                                "evidence": "Found in certificate transparency log via crt.sh",
                            }
        except Exception:
            return

    async def collect(self, timeout: int = 60) -> List[Dict]:
        """Convenience wrapper — collect all findings within `timeout` seconds into a list."""
        results = []
        async for finding in self.stream(timeout=timeout):
            results.append(finding)
        return results

    async def demo(self, timeout: int = 60):
        """Debug helper — prints findings to stdout."""
        print(f"[CertStream] Monitoring '{self.domain}' for {timeout}s …")
        async for finding in self.stream(timeout=timeout):
            print(f"  [+] {finding['fqdn']} ({finding['source']})")

