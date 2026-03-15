# Bug Bounty Recon Platform - Implementation Plan

Technical blueprint for a high-performance, signal-focused recon and intelligence platform.

## Architecture Overview

The system will follow a distributed architecture to handle long-running recon tasks asynchronously.

### Stack
- **Backend**: Python 3.12+ with FastAPI
- **Task Queue**: Celery with Redis
- **Database**: PostgreSQL (Relational mapping of domains, assets, and findings)
- **CLI**: Typer for an interactive command-line experience
- **Recon Tools**: Internal Python implementations + wrappers for industry-standard tools (`httpx`, `subfinder`)

### Project Structure
```text
recon_platform/
├── app/
│   ├── api/            # FastAPI endpoints
│   ├── core/           # Module logic (Input, Recon, JS, etc.)
│   ├── db/             # Database initialization and sessions
│   ├── models/         # SQLAlchemy/SQLModel models
│   ├── workers/        # Celery task definitions
│   └── main.py         # Application entry point
├── cli/                 # Typer-based CLI interface
├── migrations/          # Database migrations
├── tests/               # Unit and integration tests
├── requirements.txt
└── .env
```

## Proposed Changes

### Core Modules (Phase 1: MVP)

#### 1. Input Layer (`app/core/input_layer.py`)
- Target ingestion (single, multi, wildcard, CIDR).
- Scope filtering (regex rules, bug bounty program formats).

#### 2. Recon Engine (`app/core/recon_engine.py`)
- **Passive Discovery (Multi-Tool)**:
    - **Subfinder**: Fast passive subdomain discovery via APIs (VirusTotal, Shodan, Certspotter).
    - **Amass**: Deep passive + active enumeration with graph-based correlation.
    - **Assetfinder**: Lightweight supplemental discovery.
    - **crt.sh / CertStream**: Certificate transparency log scanning.
    - **theHarvester**: Email, subdomain, and host discovery from search engines.
- **Active Enumeration**: 
    - **DNS Brute Forcing**: High-speed resolution using custom wordlists.
    - **Permutations/Alterations**: Generating and probing variations of found subdomains.
    - **Zone Transfers**: Checking for misconfigured DNS servers.
- **Service Discovery**:
    - **Port Scanning**: Integration with `naabu` and `nmap` for fast discovery of non-HTTP services.
    - **Technology Fingerprinting**: Version detection for services to map against known CVEs.
- **Origin IP Discovery (Real IP Finder)**:
    - **WAF Bypass**: Identifying the actual origin IP to bypass Cloudflare/Akamai.
    - **DNS History**: Analyzing historical A records (SecurityTrails).
    - **SSL Certificate Matching**: Scanning mass-IP datasets (Censys/Shodan) for the target's SSL certificates on direct IPs.
- **Live Probing**: HTTP/HTTPS status, titles, CDN, and WAF fingerprinting.

#### 3. Advanced Crawler & Content Discovery (`app/core/crawler.py`)
- **Smart Crawling**: Hybrid BFS/DFS with loop detection and parameter discovery.
- **Directory Brute-forcing**: 
    - **Wordlist-based Fuzzing**: High-speed discovery of hidden files and directories.
    - **Extension Fuzzing**: Targeted probing for backups (`.bak`, `.old`), configs (`.env`, `.conf`), and source files (`.php`, `.asp`).
    - **Recursive Discovery**: Automatically brute-forcing newly discovered directories.
- **Asset Extraction**: Extracting JS files, JSON endpoints, and GraphQL schemas.

#### 4. JS Intelligence Engine (`app/core/js_engine.py`)
- Script extraction and endpoint/secret regex matching.

#### 5. Secret Engine (`app/core/secret_engine.py`)
- Entropy and pattern-based secret detection.

### Advanced Features (Phase 2 & 3: Elite Tooling)

#### 6. OSINT & External Data Engine
- **Search Engines**: Automated Google/Bing dorking (`site:`, `filetype:`, `inurl:`, `intitle:`).
- **Security Databases**: Integration with `Shodan`, `Censys`, and `GreyNoise`.
- **Public Code/Leaks**: Monitoring `GitHub` and `Pastebin` for target-related secrets or internal documentation.

#### 6. Internet-Wide Sensitive Data Search (`app/core/data_search.py`)
- **Google Dork Engine**: 
    - Automated dorks for config files: `site:example.com filetype:env`
    - Credentials: `site:example.com inurl:config password`
    - Exposed APIs: `site:example.com inurl:api/v1`
    - Admin panels: `site:example.com inurl:admin`
- **GitHub Deep Search**: 
    - Org-wide code scanning for secrets, tokens, DB URLs, and private keys.
    - Historical commit search for accidentally pushed credentials.
    - Gist scanning for target-domain mentions.
- **Pastebin / Leaks**: Monitor public pastes mentioning domain, emails, or internal IPs.
- **S3 / GCS Bucket Discovery**: Enumerate and probe cloud storage buckets related to target (e.g., `target-prod`, `target-backup`).
- **Social Engineering Data**: OSINT from LinkedIn (employee names), Hunter.io (emails).

#### 7. Data Management & Deduplication
- **Intelligent Merging**: Using `anew` style logic to eliminate duplicate assets from multi-tool outputs.
- **Correlation**: Linking horizontal (IP owners) and vertical (subdomain) assets to build a complete identity graph.

#### 8. AI Triage & Analysis Engine
- **LLM Scrutiny**: Feed suspicious JS snippets to an LLM to identify potential logic flaws (IDOR, Auth bypass).
- **Finding Prioritization**: Rank findings based on exploitability and business impact.
- **Auto-Reporting**: Generate Bugcrowd/HackerOne formatted reports automatically.

#### 7. Historical & OSINT Integration
- **Wayback Mining**: Integration with Wayback Machine to find historical assets and hidden endpoints.
- **GitHub Recon**: Automated scanning of target organization's public repos for leaked secrets and dev endpoints.
- **Cloud/ASN Mapping**: Broadening scope by tracking ASNs and cloud IP ranges belonging to the target.

#### 8. Visual Recon & Monitoring
- **Automated Screenshots**: Headless browser captures for every live host for quick manual review.
- **Diff Monitoring**: Track changes in subdomains, JS files, and technology stacks over time with alerts (Slack/Discord).

#### 9. Advanced JS Sink Analysis
- **Dynamic Analysis**: Trace user-controlled parameters into sensitive JS sinks (e.g., `setInnerHTML`, `eval`).
- **Source Map Reconstruction**: Automatically fetch and map `.map` files to reconstruct original source for deeper analysis.

#### 10. Vulnerability Signal Engine (High ROI Focus)
- **API Specific**: 
    - **BOLA/IDOR**: Tracking object IDs in API responses and testing for cross-user access.
    - **Mass Assignment**: Identifying endpoints that accept JSON and fuzzing for hidden fields (e.g., `is_admin`).
    - **Shadow APIs**: Detecting versioned endpoints (v2, v3) or undocumented routes.
- **Web Vulnerabilities (Injection & Logic)**:
    - **XSS (Reflected/Stored/DOM)**: Automated payload injection and context-aware reflection check.
    - **Blind XSS**: Integration with callback servers (OOB) to detect delayed triggers.
    - **CSRF Logic**: Analyzing forms and sensitive POST endpoints for missing or weak anti-CSRF protections.
    - **403/401 Bypass Suite**:
        - **Header Manipulation**: Fuzzing headers like `X-Forwarded-For`, `X-Original-URL`, `X-Custom-IP-Authorization`.
        - **Path Fuzzing**: Probing variations like `/admin/`, `/admin/.`, `/admin/./`, `/%2e/admin`.
        - **Method Overriding**: Testing `X-HTTP-Method-Override` and alternate HTTP methods (PUT, DELETE, DEBUG).
    - **SSRF (Deep Probing)**: Testing internal IP ranges, metadata endpoints, and DNS rebinding scenarios.
- **Business Logic & Bypasses** (`app/core/vuln/business_logic.py`):
    - **Race Condition Probing**: Multi-threaded "Turbo Intruder" style checks for timing-sensitive actions (checkout, voting, OTP validation).
    - **MFA/Rate Limit Bypasses**: Header-based IP spoofing (`X-Forwarded-For`) to bypass lockouts.
    - **Coupon/Discount Abuse**: Testing negative quantities, duplicate usage, and parameter manipulation in e-commerce flows.
    - **Workflow Bypass**: Skipping steps in multi-step flows (e.g., checkout steps, email verification).
    - **Privilege State Confusion**: Accessing resources from one role while authenticated as another.
- **CORS Detection & Exploitation** (`app/core/vuln/cors_engine.py`):
    - **Origin Reflection**: Detecting if any arbitrary `Origin:` header is reflected.
    - **Null Origin Bypass**: Testing `Origin: null` acceptance.
    - **Subdomain Trust**: Checking if `Origin: evil.target.com` is trusted.
    - **Exploitation PoC**: Auto-generating JavaScript exploit code for confirmed CORS issues.
    - **Pre-flight Analysis**: Checking `Access-Control-Allow-Credentials: true` combined with reflected origin.
- **Cloud & Infrastructure**:
    - **SSRF (Cloud Metadata)**: Testing for access to `169.254.169.254` and other cloud internal services.
    - **Cache Poisoning/Deception**: Analyzing response headers (Vary, Cache-Control) for misconfigured caching rules.
- **Modern Web**:
    - **Prototype Pollution**: Detecting polluted object patterns in client-side JS.
    - **JWT Manipulation**: Automated testing for `none` algorithm, weak secrets, and kid-header injection.
- **AI-Specific (Novel)**:
    - **AI Prompt Injection**: If the target has a chatbot/LLM interface, test for system prompt bypasses.
    - **MCP Security**: Identifying Model Context Protocol endpoints and testing for tool execution leaks.

#### 11. Authenticated Scan Engine
- **Session Management**: Automated cookie/token injection for authenticated crawling.
- **Session Renewal**: Rules to detect "Logged Out" states and re-authenticate via provided credentials.
- **Privilege Escalation Probing**: Running scans as different user roles to identify horizontal/vertical access flaws.

#### 12. Stealth & WAF Avoidance
- **Rate Limiting**: Configurable delays and jitter to avoid WAF triggering.
- **Proxy Support**: Support for Tor, custom VPNs, and rotating proxy services.
- **Browser Fingerprint Spoofing**: Rotating User-Agents and browser signatures.

### Database Layer (`app/models/`)
- Relational schema for targets, assets, and findings.

## Verification Plan

### Automated Tests
- `pytest` for unit/integration tests.
- Mocking external tool outputs.

### Manual Verification
- Dry-run scans against test targets.
- Inspection of generated reports.
