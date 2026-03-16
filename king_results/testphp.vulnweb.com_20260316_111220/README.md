# KING Scan — testphp.vulnweb.com
**Scan Time**: 2026-03-16T11:43:02.040190
**Tool**: KING Bug Bounty Recon Platform v1.0.0

## Quick Stats
| Metric | Count |
|--------|-------|
| Total Subdomains | 31 |
| Live Hosts | 31 |
| Assets Found | 31 |
| Total Findings | 2 |
| Critical | 0 |
| High | 0 |

## Directory Structure
| Folder | Contents |
|--------|----------|
| `01_subdomains/` | All hosts, live/dead split, by source and status code |
| `02_assets/` | URLs, JS files, extracted endpoints, interesting paths |
| `03_secrets/` | API keys, tokens, high-confidence secrets by type |
| `04_vulnerabilities/` | Findings split by severity and vulnerability class |
| `05_osint/` | GitHub leaks, employee emails, Shodan/Censys data |
| `06_reports/` | Markdown reports: summary, executive, PoC notes |

## Quick Navigation
- 🔴 **Critical/High vulns** → `04_vulnerabilities/critical.json`, `04_vulnerabilities/high.json`
- 🔑 **Secrets** → `03_secrets/high_confidence.json`
- 🌐 **Live hosts** → `01_subdomains/alive.txt`
- 📜 **Full report** → `06_reports/summary_report.md`
