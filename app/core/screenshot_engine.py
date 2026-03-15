"""
Phase 3 - Automated Screenshot Engine
Captures headless browser screenshots of all live hosts for fast visual triage.
Uses playwright if available; falls back to a lightweight HTML-snapshot via httpx.

Install playwright: pip install playwright && python -m playwright install chromium
"""
import asyncio
import base64
import os
import hashlib
import httpx
from typing import List, Dict, Optional
from datetime import datetime


# ── Output Directory ──────────────────────────────────────────────────────────

DEFAULT_SCREENSHOT_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "results", "screenshots"
)


class ScreenshotEngine:
    """
    Automated headless screenshot capture for all live assets.
    Saves images as PNG files and returns metadata for integration with reporting.
    """

    def __init__(
        self,
        output_dir: str = DEFAULT_SCREENSHOT_DIR,
        viewport_width: int = 1280,
        viewport_height: int = 800,
        timeout: int = 15,
    ):
        self.output_dir = output_dir
        self.width = viewport_width
        self.height = viewport_height
        self.timeout = timeout
        os.makedirs(self.output_dir, exist_ok=True)
        self._playwright_available = self._check_playwright()

    def _check_playwright(self) -> bool:
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False

    def _make_filename(self, url: str) -> str:
        """Generate a safe, unique filename from a URL."""
        safe = hashlib.md5(url.encode()).hexdigest()[:12]
        domain = url.split("//")[-1].split("/")[0].replace(":", "_")
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return f"{domain}_{safe}_{ts}.png"

    # ── Playwright (Full Headless Browser) ───────────────────────────────

    async def _screenshot_playwright(self, url: str) -> Optional[Dict]:
        """Capture a full rendered screenshot with Playwright (preferred)."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return None

        filename = self._make_filename(url)
        filepath = os.path.join(self.output_dir, filename)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(args=["--no-sandbox", "--disable-setuid-sandbox"])
                context = await browser.new_context(
                    viewport={"width": self.width, "height": self.height},
                    user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    ignore_https_errors=True,
                )
                page = await context.new_page()

                try:
                    await page.goto(url, timeout=self.timeout * 1000, wait_until="networkidle")
                    title = await page.title()
                    await page.screenshot(path=filepath, full_page=False)
                    await browser.close()

                    return {
                        "url": url,
                        "screenshot_path": filepath,
                        "filename": filename,
                        "title": title,
                        "method": "playwright",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                except Exception:
                    await browser.close()
                    return None
        except Exception:
            return None

    # ── Fallback: HTML Snapshot ────────────────────────────────────────────

    async def _snapshot_httpx(self, url: str) -> Optional[Dict]:
        """
        Fallback when Playwright is unavailable.
        Fetches the page HTML and saves a basic text/HTML snapshot.
        """
        filename = self._make_filename(url).replace(".png", ".html")
        filepath = os.path.join(self.output_dir, filename)

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code not in [200, 201]:
                    return None

                # Extract title
                import re
                title_m = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                title = title_m.group(1).strip()[:200] if title_m else ""

                with open(filepath, "w", encoding="utf-8", errors="replace") as f:
                    f.write(resp.text)

                return {
                    "url": url,
                    "screenshot_path": filepath,
                    "filename": filename,
                    "title": title,
                    "method": "html_snapshot",
                    "status_code": resp.status_code,
                    "timestamp": datetime.utcnow().isoformat(),
                    "note": "Install playwright for real screenshots: pip install playwright && python -m playwright install chromium",
                }
        except Exception:
            return None

    # ── Core Capture Method ───────────────────────────────────────────────

    async def capture(self, url: str) -> Optional[Dict]:
        """Capture a screenshot (or snapshot) of a URL."""
        if self._playwright_available:
            result = await self._screenshot_playwright(url)
            if result:
                return result
        # Fallback
        return await self._snapshot_httpx(url)

    # ── Batch Capture ─────────────────────────────────────────────────────

    async def capture_all(self, live_hosts: List[Dict], concurrency: int = 5) -> List[Dict]:
        """
        Capture screenshots of all live hosts with concurrency control.
        `live_hosts` should be the output from ReconEngine.probe_live().
        """
        results = []
        sem = asyncio.Semaphore(concurrency)

        async def bounded_capture(host: Dict):
            url = host.get("url", "")
            if not url or not host.get("is_alive", False):
                return None
            async with sem:
                result = await self.capture(url)
                if result:
                    # Merge host metadata
                    result["server"] = host.get("server", "")
                    result["cdn"] = host.get("cdn_name", "")
                    result["status_code"] = host.get("status_code", "")
                    results.append(result)
                return result

        tasks = [bounded_capture(h) for h in live_hosts]
        await asyncio.gather(*tasks)

        print(f"[ScreenshotEngine] Captured {len(results)}/{len(live_hosts)} screenshots → {self.output_dir}")
        return results

    def generate_gallery_html(self, results: List[Dict]) -> str:
        """
        Generate a simple HTML gallery report for rapid visual triage.
        Returns HTML string (save to file separately).
        """
        rows = ""
        for r in results:
            path = r.get("screenshot_path", "")
            method = r.get("method", "")
            if method == "playwright" and path.endswith(".png"):
                # Embed as base64 for portability
                try:
                    with open(path, "rb") as f:
                        b64 = base64.b64encode(f.read()).decode()
                    img_tag = f'<img src="data:image/png;base64,{b64}" style="max-width:600px;border:1px solid #333;">'
                except Exception:
                    img_tag = f'<a href="{path}">[screenshot]</a>'
            else:
                img_tag = f'<a href="{path}" target="_blank">[HTML Snapshot]</a>'

            rows += f"""
            <tr>
                <td><a href="{r['url']}" target="_blank">{r['url']}</a></td>
                <td>{r.get('title','')}</td>
                <td>{r.get('status_code','')}</td>
                <td>{r.get('cdn','')}</td>
                <td>{img_tag}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html><head><title>Screenshot Gallery</title>
<style>
body{{font-family:monospace;background:#1a1a2e;color:#ccc;padding:20px;}}
table{{border-collapse:collapse;width:100%;}}
th,td{{border:1px solid #333;padding:8px;text-align:left;}}
th{{background:#16213e;color:#0f3460;}}
a{{color:#e94560;}}
img{{max-width:400px;height:auto;}}
</style></head>
<body>
<h1>🔍 Live Host Screenshot Gallery</h1>
<p>Generated: {datetime.utcnow().isoformat()}Z | Total: {len(results)}</p>
<table>
<tr><th>URL</th><th>Title</th><th>Status</th><th>CDN</th><th>Screenshot</th></tr>
{rows}
</table>
</body></html>"""
