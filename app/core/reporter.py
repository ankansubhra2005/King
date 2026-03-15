"""
KING — Beautiful Report Engine
Generates a portable, high-aesthetic HTML dashboard for scan results.
Features glassmorphism, dark theme, and embedded screenshots.
"""
import os
import json
import base64
from datetime import datetime
from typing import Dict, List, Optional


class BeautifulReporter:
    def __init__(self, scan_dir: str):
        self.scan_dir = scan_dir
        self.report_path = os.path.join(scan_dir, "06_reports", "dashboard.html")
        os.makedirs(os.path.dirname(self.report_path), exist_ok=True)

    def _embed_image(self, img_path: str) -> str:
        """Read image and return base64 data URI."""
        try:
            if not os.path.exists(img_path):
                return ""
            with open(img_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode()
            ext = os.path.splitext(img_path)[1].replace(".", "")
            return f"data:image/{ext};base64,{b64}"
        except Exception:
            return ""

    def generate(self, results: Dict, meta: Dict) -> str:
        """Generate the full HTML dashboard."""
        domain = meta.get("domain", "Unknown")
        ts = meta.get("scan_timestamp", datetime.now().isoformat())
        
        # ── Data Preparation ──────────────────────────────────────────────────
        findings = results.get("findings", [])
        subdomains = results.get("subdomains", [])
        alive_subs = [s for s in subdomains if s.get("is_alive")]
        screenshots = results.get("screenshots", [])
        
        # ── Component: Findings ────────────────────────────────────────────────
        findings_html = ""
        sev_class = {
            "CRITICAL": "sev-critical",
            "HIGH": "sev-high",
            "MEDIUM": "sev-medium",
            "LOW": "sev-low",
            "INFO": "sev-info"
        }
        for f in findings[:100]:
            sev = f.get("severity", "info").upper()
            findings_html += f"""
            <div class="finding-card {sev_class.get(sev, 'sev-info')}">
                <div class="card-header">
                    <span class="sev-badge">{sev}</span>
                    <span class="score-badge">{f.get('risk_score', '0.0')}</span>
                    <h3>{f.get('type', 'Finding')}</h3>
                </div>
                <div class="card-body">
                    <p class="url">{f.get('url', 'N/A')}</p>
                    <p class="evidence">{f.get('evidence', '')[:200]}</p>
                </div>
            </div>
            """

        # ── Component: Gallery ────────────────────────────────────────────────
        gallery_html = ""
        for s in screenshots:
            img_uri = self._embed_image(s.get("screenshot_path", ""))
            if not img_uri: continue
            
            gallery_html += f"""
            <div class="gallery-item">
                <img src="{img_uri}" loading="lazy" onclick="openModal('{img_uri}')">
                <div class="gallery-meta">
                    <p>{s.get('url', '')}</p>
                    <span>{s.get('title', '')[:50]}</span>
                </div>
            </div>
            """

        # ── Final HTML ────────────────────────────────────────────────────────
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KING Dashboard — {domain}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0a0b10;
            --surface: #161b22;
            --surface-accent: #21262d;
            --text: #c9d1d9;
            --text-dim: #8b949e;
            --accent: #58a6ff;
            --critical: #ff4444;
            --high: #ff8c00;
            --medium: #ffcc00;
            --low: #2ecc71;
            --info: #3498db;
        }}

        * {{ box-sizing: border-box; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: 'Inter', sans-serif;
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}

        header {{
            padding: 40px 20px;
            background: linear-gradient(180deg, rgba(88, 166, 255, 0.1) 0%, transparent 100%);
            border-bottom: 1px solid var(--surface-accent);
            text-align: center;
        }}

        .brand {{ font-weight: 800; color: #f0883e; font-size: 24px; margin-bottom: 5px; }}
        h1 {{ font-size: 48px; margin: 0; letter-spacing: -1px; }}
        .meta {{ color: var(--text-dim); font-family: 'JetBrains Mono', monospace; font-size: 14px; margin-top: 10px; }}

        .container {{ max-width: 1400px; margin: 0 auto; padding: 40px 20px; }}

        /* Stats Grid */
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: var(--surface);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid var(--surface-accent);
            text-align: center;
        }}
        .stat-card h4 {{ margin: 0; color: var(--text-dim); text-transform: uppercase; font-size: 12px; letter-spacing: 1px; }}
        .stat-card p {{ margin: 5px 0 0; font-size: 28px; font-weight: 600; }}

        /* Layout */
        .grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 30px;
        }}

        /* Findings */
        .findings-section h2 {{ margin-top: 0; display: flex; align-items: center; gap: 10px; }}
        .findings-list {{ display: grid; gap: 15px; }}
        .finding-card {{
            background: var(--surface);
            border-radius: 12px;
            border-left: 4px solid var(--info);
            padding: 20px;
            transition: transform 0.2s;
            cursor: pointer;
        }}
        .finding-card:hover {{ transform: translateX(5px); background: var(--surface-accent); }}
        
        .sev-critical {{ border-left-color: var(--critical); }}
        .sev-high {{ border-left-color: var(--high); }}
        .sev-medium {{ border-left-color: var(--medium); }}
        .sev-low {{ border-left-color: var(--low); }}
        .sev-info {{ border-left-color: var(--info); }}

        .card-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }}
        .card-header h3 {{ margin: 0; font-size: 18px; }}
        .sev-badge {{
            font-size: 10px; font-weight: 800; padding: 2px 8px; border-radius: 4px;
            background: rgba(255,255,255,0.1);
        }}
        .score-badge {{ background: #21262d; padding: 2px 8px; border-radius: 4px; font-weight: 600; color: var(--high); }}

        .url {{ color: var(--accent); font-family: 'JetBrains Mono', monospace; font-size: 13px; word-break: break-all; margin: 0; }}
        .evidence {{ color: var(--text-dim); font-size: 13px; margin: 10px 0 0; }}

        /* Gallery */
        .gallery-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 40px;
        }}
        .gallery-item {{
            background: var(--surface);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--surface-accent);
        }}
        .gallery-item img {{ width: 100%; height: 150px; object-fit: cover; cursor: pointer; transition: opacity 0.2s; }}
        .gallery-item img:hover {{ opacity: 0.8; }}
        .gallery-meta {{ padding: 12px; }}
        .gallery-meta p {{ margin: 0; font-size: 12px; color: var(--accent); word-break: break-all; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .gallery-meta span {{ font-size: 11px; color: var(--text-dim); }}

        /* Modal */
        #modal {{
            display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.9); z-index: 1000; align-items: center; justify-content: center;
            padding: 40px;
        }}
        #modal img {{ max-width: 100%; max-height: 100%; border-radius: 8px; box-shadow: 0 0 50px rgba(0,0,0,0.5); }}

        @media (max-width: 1000px) {{
            .grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>

<header>
    <div class="brand">♛ KING RECON</div>
    <h1>{domain}</h1>
    <p class="meta">Scan completed at {ts}</p>
</header>

<div class="container">
    <div class="stats">
        <div class="stat-card">
            <h4>Total Findings</h4>
            <p>{len(findings)}</p>
        </div>
        <div class="stat-card">
            <h4>Critical/High</h4>
            <p style="color: var(--critical)">{meta.get('critical_count', 0) + meta.get('high_count', 0)}</p>
        </div>
        <div class="stat-card">
            <h4>Subdomains</h4>
            <p>{len(alive_subs)}</p>
        </div>
        <div class="stat-card">
            <h4>Assets</h4>
            <p>{meta.get('total_assets', 0)}</p>
        </div>
    </div>

    <div class="findings-section">
        <h2>🎯 Security Findings</h2>
        <div class="findings-list">
            {findings_html}
        </div>
    </div>

    <div class="gallery-section">
        <h2 style="margin-top: 60px;">📸 Screenshot Gallery</h2>
        <div class="gallery-grid">
            {gallery_html}
            {"<p style='color: var(--text-dim)'>No screenshots captured. Did you install Playwright?</p>" if not gallery_html else ""}
        </div>
    </div>
</div>

<div id="modal" onclick="closeModal()">
    <img id="modal-img" src="">
</div>

<script>
    function openModal(uri) {{
        document.getElementById('modal-img').src = uri;
        document.getElementById('modal').style.display = 'flex';
    }}
    function closeModal() {{
        document.getElementById('modal').style.display = 'none';
    }}
</script>

</body>
</html>
"""
        with open(self.report_path, "w", encoding="utf-8") as f:
            f.write(html)
        
        return self.report_path
