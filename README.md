# 🕵️ Bug Bounty Recon Platform

**Elite, automated recon platform for serious bug bounty hunters.**

> Signal > Noise. Automation > Raw Data. Prioritization > Dumping findings.

---

## ⚡ Phase 1 Features (MVP)

| Module | Description |
|---|---|
| 🎯 Input Layer | Scope-aware target ingestion (wildcard, CIDR, file) |
| 🔍 Recon Engine | Passive + Active subdomain enum, Origin IP finder |
| 🕸️ Crawler | BFS/DFS crawl + directory brute-forcing + extension fuzzing |
| 📜 JS Engine | JS download, endpoint extraction, source map resolution |
| 🔐 Secret Engine | 20+ patterns + Shannon entropy detection |
| ⚡ CLI | Rich terminal UI with progress bars + JSON/Markdown export |

---

## 🚀 Quick Start

### 1. Setup

```bash
# Clone and enter project
cd "Bug Bounty"

# Create virtual environment
python -m venv venv
source venv/bin/activate   # Linux/Mac
# venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt

# Copy env config
cp .env.example .env
# Edit .env with your API keys
```

### 2. Start services

```bash
# Redis (required for Celery)
docker run -d -p 6379:6379 redis:alpine

# PostgreSQL
docker run -d -p 5432:5432 \
  -e POSTGRES_DB=recon_db \
  -e POSTGRES_USER=user \
  -e POSTGRES_PASSWORD=password \
  postgres:15-alpine
```

### 3. Start the API

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 4. Start Celery worker

```bash
celery -A app.workers.celery_app worker --loglevel=info
```

### 5. Use the CLI

```bash
# Full scan
python -m cli.main scan example.com

# Passive only + output
python -m cli.main scan example.com --passive --output results.json

# Custom modules
python -m cli.main scan example.com --module subdomain --module secrets

# With scope rules
python -m cli.main scan example.com \
  --scope "*.example.com" \
  --exclude "payments.example.com"
```

---

## 🗂️ Project Structure

See [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)

## 📋 Development Checklist

See [DEVELOPMENT_CHECKLIST.md](DEVELOPMENT_CHECKLIST.md)

## 📐 Implementation Plan

See [implementation_plan.md](implementation_plan.md)

---

## ⚠️ Legal Disclaimer

This tool is intended **only for authorized security testing** within the scope of bug bounty programs you are permitted to test. Unauthorized scanning is illegal. Always respect program scope and rules of engagement.
# King
