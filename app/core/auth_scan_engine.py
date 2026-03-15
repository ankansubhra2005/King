"""
Phase 3 - Authenticated Scan Engine
Manages session injection for authenticated crawling and scanning.
Provides:
- Cookie/Token injection for all scan modules
- Automatic session renewal (handles logout detection)
- Role-based privilege probing (multi-session scan)
"""
import asyncio
import httpx
import re
from typing import List, Dict, Optional, Union
from dataclasses import dataclass, field


# ── Session Representation ────────────────────────────────────────────────────

@dataclass
class ScanSession:
    """Represents an authenticated browser/API session."""
    name: str                           # e.g. "admin", "regular_user", "guest"
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)  # e.g. Authorization: Bearer ...
    login_url: Optional[str] = None     # URL to re-authenticate if session expires
    login_data: Optional[dict] = None   # POST data for re-auth
    logout_indicators: List[str] = field(default_factory=lambda: [
        "login", "sign in", "session expired", "401", "unauthorized",
    ])

    def to_httpx_kwargs(self) -> dict:
        """Return headers + cookies as kwargs for httpx.AsyncClient."""
        return {
            "headers": {"User-Agent": "Mozilla/5.0", **self.headers},
            "cookies": self.cookies,
        }


# ── Session Renewal ────────────────────────────────────────────────────────────

class SessionManager:
    """
    Handles session lifecycle — injecting credentials and renewing expired sessions.
    """

    def __init__(self, sessions: List[ScanSession]):
        self.sessions = sessions

    def is_logged_out(self, response_text: str, url: str, session: ScanSession) -> bool:
        """Detect if a response indicates an expired/invalid session."""
        lower = response_text.lower()
        return any(ind in lower for ind in session.logout_indicators)

    async def renew_session(self, session: ScanSession) -> bool:
        """
        Re-authenticate using provided login_url and login_data.
        Updates session.cookies in-place.
        Returns True if renewal succeeded.
        """
        if not session.login_url or not session.login_data:
            return False

        try:
            async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
                resp = await client.post(
                    session.login_url,
                    data=session.login_data,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if resp.status_code in [200, 302]:
                    # Update cookies from response
                    session.cookies.update(dict(resp.cookies))
                    # Try to extract JWT from response body
                    try:
                        body = resp.json()
                        for key in ["token", "access_token", "jwt", "authToken"]:
                            if key in body:
                                session.headers["Authorization"] = f"Bearer {body[key]}"
                                break
                    except Exception:
                        pass
                    return True
        except Exception:
            pass
        return False

    async def request_with_auth(
        self,
        session: ScanSession,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[httpx.Response]:
        """
        Make a request using the session's credentials.
        Auto-renews if session is detected as expired.
        """
        client_kwargs = session.to_httpx_kwargs()
        client_kwargs["headers"].update(kwargs.pop("headers", {}))

        max_retries = 2
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(
                    verify=False, timeout=15, follow_redirects=True, **client_kwargs
                ) as client:
                    resp = await client.request(method, url, **kwargs)

                    # Check for session expiry
                    if self.is_logged_out(resp.text, url, session):
                        if attempt == 0:
                            renewed = await self.renew_session(session)
                            if renewed:
                                client_kwargs = session.to_httpx_kwargs()
                                continue
                        return None
                    return resp
            except Exception:
                break
        return None


# ── Authenticated Crawler Integration ─────────────────────────────────────────

class AuthenticatedCrawler:
    """
    Extends basic crawling with session-aware requests.
    Feeds authenticated HTTP responses to other scan modules.
    """

    def __init__(self, session: ScanSession):
        self.session = session
        self.manager = SessionManager([session])

    async def fetch(self, url: str) -> Optional[Dict]:
        """Fetch a URL with authentication credentials."""
        resp = await self.manager.request_with_auth(self.session, "GET", url)
        if not resp:
            return None
        return {
            "url": url,
            "status_code": resp.status_code,
            "body": resp.text,
            "headers": dict(resp.headers),
            "session_name": self.session.name,
        }

    async def crawl(self, urls: List[str], concurrency: int = 10) -> List[Dict]:
        """Crawl a list of URLs using authenticated session."""
        sem = asyncio.Semaphore(concurrency)
        results = []

        async def bounded_fetch(url):
            async with sem:
                result = await self.fetch(url)
                if result:
                    results.append(result)

        await asyncio.gather(*[bounded_fetch(u) for u in urls])
        return results


# ── Privilege Escalation Probing ───────────────────────────────────────────────

class PrivilegeEscalationProber:
    """
    Runs the same set of requests across multiple sessions with different privilege levels.
    Detects endpoints where a lower-privilege session can access higher-privilege data.
    """

    def __init__(self, sessions: List[ScanSession]):
        self.sessions = sessions
        self.manager = SessionManager(sessions)

    async def _fetch_with_session(self, session: ScanSession, url: str) -> Dict:
        resp = await self.manager.request_with_auth(session, "GET", url)
        return {
            "session": session.name,
            "url": url,
            "status": resp.status_code if resp else None,
            "body_snippet": resp.text[:300] if resp else None,
            "content_length": len(resp.text) if resp else 0,
        }

    async def compare_access(self, url: str) -> List[Dict]:
        """
        Fetch the same URL across all sessions and compare responses.
        Flag anomalies where a low-priv session gets data a high-priv session does.
        """
        tasks = [self._fetch_with_session(s, url) for s in self.sessions]
        results = await asyncio.gather(*tasks)

        findings = []
        # Simple heuristic: if any lower-indexed (lower-priv) session gets 200
        # while we expected 403, flag it
        for i, result in enumerate(results):
            if result["status"] == 200:
                # Check if other sessions also got 200 with same content
                other_200s = [r for j, r in enumerate(results) if j != i and r["status"] == 200]
                if not other_200s:
                    # Only this session got 200 — potential anomaly
                    findings.append({
                        "type": "Authenticated Scan — Privilege Anomaly",
                        "url": url,
                        "session": result["session"],
                        "status": result["status"],
                        "severity": "high",
                        "confidence": 0.65,
                        "evidence": f"Session '{result['session']}' uniquely received HTTP 200 on {url}",
                        "suggested_next_step": "Compare response body to privileged session. Confirm unauthorized data access.",
                    })

        return findings

    async def probe_all(self, urls: List[str]) -> List[Dict]:
        """Run privilege comparison across all provided URLs."""
        all_findings = []
        tasks = [self.compare_access(url) for url in urls[:50]]
        results = await asyncio.gather(*tasks)
        for r in results:
            all_findings.extend(r)
        return all_findings


# ── Authenticated Scan Engine (Orchestrator) ───────────────────────────────────

class AuthenticatedScanEngine:
    """
    Main orchestrator for authenticated scanning.
    Accepts one or more ScanSession objects and runs crawls + privilege probing.
    """

    def __init__(self, sessions: List[ScanSession]):
        self.sessions = sessions
        self.prober = PrivilegeEscalationProber(sessions)

    @classmethod
    def from_cookies(cls, name: str, cookies: Dict[str, str]) -> "AuthenticatedScanEngine":
        """Quick constructor for cookie-based sessions."""
        return cls([ScanSession(name=name, cookies=cookies)])

    @classmethod
    def from_bearer_token(cls, name: str, token: str) -> "AuthenticatedScanEngine":
        """Quick constructor for Bearer token sessions."""
        return cls([ScanSession(name=name, headers={"Authorization": f"Bearer {token}"})])

    @classmethod
    def from_credentials(
        cls,
        sessions_config: List[Dict],
    ) -> "AuthenticatedScanEngine":
        """
        Construct from a list of session configs.
        Each config: {"name": str, "cookies": {}, "headers": {}, "login_url": ..., "login_data": ...}
        """
        sessions = []
        for cfg in sessions_config:
            sessions.append(ScanSession(
                name=cfg.get("name", "unnamed"),
                cookies=cfg.get("cookies", {}),
                headers=cfg.get("headers", {}),
                login_url=cfg.get("login_url"),
                login_data=cfg.get("login_data"),
            ))
        return cls(sessions)

    async def crawl_as(self, session_name: str, urls: List[str]) -> List[Dict]:
        """Crawl URLs as a specific named session."""
        session = next((s for s in self.sessions if s.name == session_name), None)
        if not session:
            raise ValueError(f"No session named '{session_name}'")
        crawler = AuthenticatedCrawler(session)
        return await crawler.crawl(urls)

    async def probe_privilege_escalation(self, urls: List[str]) -> List[Dict]:
        """Test privilege escalation across all sessions for the given URLs."""
        return await self.prober.probe_all(urls)

    async def scan(self, urls: List[str]) -> Dict:
        """
        Full authenticated scan:
        1. Crawl all URLs as each session
        2. Probe for privilege escalation across sessions
        Returns a dict with 'crawl_results' and 'escalation_findings'.
        """
        crawl_results = {}
        for session in self.sessions:
            crawler = AuthenticatedCrawler(session)
            crawl_results[session.name] = await crawler.crawl(urls)

        escalation_findings = await self.probe_privilege_escalation(urls)

        return {
            "crawl_results": crawl_results,
            "escalation_findings": escalation_findings,
        }
