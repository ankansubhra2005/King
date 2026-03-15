# ♛ KING — Bug Bounty Recon Platform

**Elite, automated recon platform for serious bug bounty hunters.**

> Signal > Noise. Automation > Raw Data. Prioritization > Dumping findings.

---

## ⚡ Features

| Module | Description |
|---|---|
| 🎯 **Bulk Scanning** | Scan hundreds of domains from a file with unique results folders per target. |
| 🔍 **Multi-Tool Recon** | Subdomain discovery via `subfinder`, `amass`, `crt.sh`, and more. |
| 🕸️ **Advanced Crawler** | `katana`, `gospider`, `ffuf`, and `feroxbuster` for deep endpoint discovery. |
| 🔐 **Secret Hunting** | `trufflehog` + `gitleaks` + internal regex for finding API keys/tokens. |
| 💀 **OWASP Engines** | Integrated **SQLi**, **LFI**, **XSS**, **SSRF**, and **Security Headers** modules. |
| 📜 **JS Intelligence** | Complete JS analysis, endpoint extraction, and source map resolution. |
| 📺 **Live Output** | Real-time streaming tool output — see findings as they happen. |
| 🤖 **AI Triage** | Automated analysis and reporting of high-risk findings. |
| ✨ **Beautiful Report** | Premium HTML dashboard with **OWASP Top 10** category mapping. |

---

## 🚀 Quick Start

### 1. Setup

```bash
# Clone and enter project
cd "Bug Bounty"

# Create virtual environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Setup external tools (Recommended)
# go install github.com/hahwul/dalfox/v2@latest
# go install github.com/projectdiscovery/katana/cmd/katana@latest
# ... see walkthrough.md for full tool list
```

### 2. Basic Command Structure

```bash
python -m cli.main scan <domain> [options]
```

### 3. Command Combinations

#### 🎯 Bulk Targeting
Scan every domain in a file sequentially with live output.
```bash
python -m cli.main scan --targets domains.txt -v
```

#### 📺 Live Verbose Mode
Stream every discovery, URL, and finding live to your terminal.
```bash
python -m cli.main scan example.com -v
```

#### 📖 Custom Wordlists
Use your own wordlists for directory/endpoint discovery (ffuf, feroxbuster).
```bash
python -m cli.main scan example.com -w /path/to/wordlist.txt
```

#### 💀 Focused Vulnerability Scan
Disable full recon and focus only on specific modules with blind XSS callback.
```bash
python -m cli.main scan example.com -m xss -m secrets --blind-xss https://cb.example.net -v
```

#### 🛡️ Passive Recon Only
Gather data without sending any traffic to the target servers.
```bash
python -m cli.main scan example.com --passive --output-dir ./osint_results
```

#### 🤖 AI-Powered Analysis
Generate detailed triage reports for every high/critical finding.
```bash
python -m cli.main scan example.com --ai-report
```

---

## 🛠️ External Dependencies

KING leverages several industry-standard tools for maximum coverage. While KING works out of the box using internal engines, installing these will significantly enhance your results.

### Discovery & Recon
- [**subfinder**](https://github.com/projectdiscovery/subfinder) — Fast subdomain discovery.
- [**amass**](https://github.com/owasp-amass/amass) — In-depth subdomain enumeration.
- [**katana**](https://github.com/projectdiscovery/katana) — Next-gen web crawling framework.
- [**gospider**](https://github.com/jaeles-project/gospider) — High-performance web spidering.
- [**ffuf**](https://github.com/ffuf/ffuf) — Fast web fuzzer for directory discovery.
- [**feroxbuster**](https://github.com/epi052/feroxbuster) — Recursive directory brute-forcing.

### Vulnerability Analysis
- [**dalfox**](https://github.com/hahwul/dalfox) — Parameter analysis and XSS scanning.
- [**XSStrike**](https://github.com/s0md3v/XSStrike) — Advanced XSS detection suite.
- [**kxss**](https://github.com/Emoe/kxss) — Detection of reflected special characters.
- [**byp4xx**](https://github.com/lobuhi/byp4xx) — 403 Forbidden bypasser.
- [**4-Zero-3**](https://github.com/Dheerajmadhukar/4-Zero-3) — Comprehensive 403 bypass toolkit.

### Secrets & Visuals
- [**trufflehog**](https://github.com/trufflesecurity/trufflehog) — Deep secret scanning for keys/tokens.
- [**gitleaks**](https://github.com/gitleaks/gitleaks) — Git-based secret discovery.
- [**playwright**](https://github.com/microsoft/playwright-python) — Headless browser for screenshot capture.

---

## ⚙️ CLI Options Reference

| Flag | Short | Description |
|---|---|---|
| `domain` | - | Target domain (e.g., example.com) |
| `--targets` | `-T` | File containing list of target domains |
| `--module` | `-m` | Specific module(s) to run (subdomain, xss, crawler, etc.) |
| `--verbose` | `-v` | Live streaming mode for all active tools |
| `--wordlist` | `-w` | Custom wordlist for discovery tools |
| `--output-dir` | `-d` | Root folder for structured results |
| `--passive` | - | Passive reconnaissance only |
| `--threads` | `-t` | Max concurrency threads (default: 30) |
| `--blind-xss` | - | Blind XSS callback URL |
| `--oob` | - | OOB callback server for SSRF |

---

## 🗂️ Results Structure

Results are saved to `king_results/<domain>_<timestamp>/` with a clean hierarchy:
- `01_subdomains/` — Alive hosts, status codes, sources.
- `02_assets/` — All URLs, JS files, extracted endpoints.
- `03_secrets/` — API keys, tokens (high confidence).
- `04_vulnerabilities/` — XSS, 403 bypasses, etc.
- `05_osint/` — GitHub leaks, Shodan data.
- `06_reports/` — Human-readable Markdown reports.

---

## ⚠️ Legal Disclaimer

This tool is intended **only for authorized security testing**. Unauthorized scanning is illegal. Always respect program scope.
