# The Altimate King — Scan: scanme.nmap.org
**Scan Time**: 2026-03-16T13:33:50.481872
**Tool**: The Altimate King — Bug Bounty Recon Platform v1.0.0

## Quick Stats
| Metric | Count |
|--------|-------|
| Total Subdomains | 1 |
| Live Hosts | 0 |
| Assets Found | 0 |
| Total Findings | 1 |
| Open Ports | 1 |
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
| `07_network/` | Open ports, service versions, categorized by port number |

## Quick Navigation
- 🔴 **Critical/High vulns** → `04_vulnerabilities/critical.json`, `04_vulnerabilities/high.json`
- 🔑 **Secrets** → `03_secrets/high_confidence.json`
- 🌐 **Live hosts** → `01_subdomains/alive.txt`
- 🔌 **Open Ports** → `07_network/open_ports.json`
- 📜 **Full report** → `06_reports/summary_report.md`
