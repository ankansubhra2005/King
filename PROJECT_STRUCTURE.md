The Altimate King — Project Structure

the-altimate-king/
├── app/
│   ├── api/                # FastAPI logic (WIP)
│   │   ├── router.py
│   │   └── endpoints/
│   ├── core/               # Modular Recon Engines (The Heart)
│   │   ├── recon_engine.py      # Subdomain & Alive host discovery
│   │   ├── crawler.py           # BFS Crawler & Directory Brute
│   │   ├── js_engine.py         # endpoint & secret extractor
│   │   ├── network_engine.py    # Nmap port scanning
│   │   ├── secret_engine.py     # Regex & Entropy secrets
│   │   ├── osint_engine.py      # GitHub, Shodan, OSINT
│   │   ├── bypass_engine.py     # WAF/Firewall bypasses
│   │   ├── vuln_engines/        # Domain-specific scanners (SQLi, XSS, etc.)
│   │   ├── ai_engine.py         # AI Triage & Analysis
│   │   ├── verbose.py           # Real-time streaming logger
│   │   └── report_writer.py     # HTML/PDF/MD generator
│   ├── db/                 # DB management
│   ├── models/             # Shared data models
│   └── workers/            # Celery background tasks
├── cli/                    # CLI Entry Point (Typer)
│   └── main.py              # The "king" command logic
├── wordlists/              # Default recon wordlists
├── tests/                  # Pytest suite
├── migrations/             # Database migrations
├── .env.example            # Template for API keys
├── .gitignore              # Git exclusion rules
├── pyproject.toml          # Project metadata & Entry points
├── requirements.txt        # Python dependencies
└── README.md               # User & Hacker manual
