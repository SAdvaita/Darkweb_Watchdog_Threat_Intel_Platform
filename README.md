# 🛡️ DarkWeb Watchdog

[![CI](https://github.com/YOUR_USERNAME/darkweb-watchdog/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/darkweb-watchdog/actions)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-green.svg)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Canary-validated external exposure intelligence platform** — answers the SOC question:  
> *"Has anything belonging to my organization shown up somewhere it shouldn't be?"*

---

## What It Does

DarkWeb Watchdog continuously monitors public internet sources for signs of organizational data exposure:

| Source | What It Monitors |
|---|---|
| **ransomware.live** | Ransomware group leak-site victim listings |
| **Hudson Rock Cavalier** | Infostealer compromise statistics for your domains |
| **Certificate Transparency (crt.sh)** | New TLS certificates — subdomains and lookalike typosquats |
| **GitHub Gists & Events** | Public code/gists containing credentials or secrets |
| **AlienVault OTX** | Threat intelligence pulses and IOC feeds |
| **abuse.ch ThreatFox** | Malware command-and-control indicators |

Findings are scored, correlated in a **knowledge graph**, and surfaced as **SLA-tracked cases** with MITRE ATT&CK mappings.

---

## Key Features

- 🕯️ **Canary-validated detection** — plant tracers, measure real time-to-detect
- 🔍 **Detection-as-code** — 12 versioned YAML rules with unit tests (Sigma-style)
- 🕸️ **Exposure knowledge graph** — NetworkX blast-radius and shortest-path analysis
- 📊 **Explainable scoring** — severity + confidence with full breakdown
- 🔒 **Privacy-by-design** — secrets redacted before storage, hash-chained audit log
- 📤 **STIX 2.1 export** + ATT&CK Navigator layer + PDF report
- 🔔 **Telegram + Slack alerts** for high/critical findings
- ♻️ **Replay mode** — recorded fixtures for testing and demo without network

---

## Quick Start

### 1. Clone and configure
```bash
git clone https://github.com/YOUR_USERNAME/darkweb-watchdog
cd darkweb-watchdog
cp .env.example .env
# Edit .env — add WATCHED_DOMAINS and optional API keys
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run
```bash
uvicorn app.main:app --reload --port 8000
```

- **Interactive SOC Dashboard**: Open **http://localhost:8000/dashboard** (or `http://localhost:8000/`) for the dark-mode SOC triage UI with live SSE feeds, Cytoscape knowledge graph, Kanban incident board, and Canary Lab.
- **Interactive OpenAPI Documentation**: Open **http://localhost:8000/docs** for the Swagger UI.

### 4. Run the 7-Step End-to-End Demo
```bash
python demo.py
```
This runs a simulated live SOC engagement:
1. Provisions root perimeter and crown-jewel assets
2. Plants a canary tracer token
3. Ingests feeds through the normalizer & redaction pipeline
4. Verifies privacy-by-design cryptographic secret redaction
5. Evaluates explainable multi-factor scoring and SLA timers
6. Computes NetworkX exposure graph topology and blast radius
7. Validates canary Time-to-Detect (TTD) and SHA-256 tamper-evident audit hash chain

### Docker
```bash
docker compose up --build
```

---

## Configuration (`.env`)

| Variable | Description | Required |
|---|---|---|
| `WATCHED_DOMAINS` | Comma-separated domains to monitor | ✅ |
| `GITHUB_TOKEN` | GitHub PAT for higher rate limits | Recommended |
| `ALIENVAULT_OTX_KEY` | Free OTX API key | Optional |
| `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | Alert notifications | Optional |
| `SLACK_WEBHOOK_URL` | Slack alert notifications | Optional |
| `REPLAY_MODE` | Use fixture files instead of live APIs | For testing |

All keys are **free tier** — no paid services required.

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/findings` | List findings (filter by severity, status) |
| GET | `/findings/{id}` | Get a single finding with score breakdown |
| PATCH | `/findings/{id}` | Update finding status |
| GET | `/cases` | List cases (Kanban-ready) |
| POST | `/cases` | Create a case from findings |
| GET | `/stream` | Server-Sent Events live feed |
| GET | `/graph` | Full exposure graph (nodes + edges) |
| GET | `/graph/blast-radius/{asset_id}` | Blast radius for an asset |
| GET | `/rules` | List all detection rules |
| POST | `/rules/test` | Test text against all rules |
| POST | `/canaries/plant` | Plant a canary gist |
| GET | `/canaries` | List canaries + detection status |
| GET | `/sources/health` | Collector health (last success, errors) |
| GET | `/metrics/summary` | Dashboard summary metrics |
| GET | `/export/stix` | STIX 2.1 bundle |
| GET | `/export/navigator` | ATT&CK Navigator layer |
| GET | `/export/report.pdf` | PDF exposure report |
| GET | `/audit/verify` | Verify audit log chain integrity |
| POST | `/collect/run` | Manually trigger a collector run |

---

## Detection Rules

| Rule ID | Category | MITRE ATT&CK | Base Score |
|---|---|---|---|
| DWW-CRED-001 | Corporate email + password pair | T1589.001, T1078 | 40 |
| DWW-CRED-002 | Credential pair (semicolon) | T1589.001, T1078 | 40 |
| DWW-CRED-003 | .env file with credentials | T1552.001 | 40 |
| DWW-SECRET-001 | Private key in public content | T1552.001, T1593.003 | 40 |
| DWW-SECRET-002 | Cloud API key (AKIA format) | T1552.001 | 40 |
| DWW-INFOSTEAL-001 | Infostealer exposure (Hudson Rock) | T1555.003, T1078 | 45 |
| DWW-RANSOM-001 | Own org on ransomware site | T1486 | **80** |
| DWW-RANSOM-002 | Vendor on ransomware site | T1195 | 35 |
| DWW-LOOKALIKE-001 | Lookalike domain certificate | T1583.001, T1566 | 30 |
| DWW-INFRA-001 | Infrastructure mention | T1596 | 25 |
| DWW-IOC-001 | Watched asset in IOC feed | T1583 | 25 |
| DWW-CANARY-001 | Planted canary marker detected | n/a | 0 |

---

## Running Tests

```bash
pytest tests/ -v
```

The CI gate requires:
- All rules have positive **and** negative tests
- Secrets are redacted before database storage
- Audit chain detects tampering
- All collectors have respx-mocked tests + fixture replay

---

## Architecture

```
Collectors → Normalizer (redact + fingerprint) → Rule Engine
    → Graph Correlator → Scorer → Case Manager → Notifiers + Dashboard
```

**Tech Stack**: Python 3.11, FastAPI, httpx, APScheduler, SQLModel, SQLite,  
NetworkX, React, Vite, Tailwind, Cytoscape.js, Docker, GitHub Actions, STIX 2.1

---

## Ethical Guardrails

- ✅ Monitor only assets you own or have written permission to monitor
- ✅ Passive collection only — public APIs respecting rate limits and ToS
- ❌ No Tor crawling, no criminal forum access, no downloading stolen datasets
- ❌ Never test leaked credentials against live systems
- ✅ Secrets redacted before storage — privacy-by-design

---

## Resume Wording

> **DarkWeb Watchdog | External Exposure Intelligence Platform**  
> Built a canary-validated exposure monitoring platform that ingests live ransomware leak-site, infostealer, certificate-transparency and GitHub feeds, applies versioned detection-as-code rules mapped to MITRE ATT&CK, correlates findings in an asset exposure graph, and measures time to detect with planted tracer data, with SLA-tracked case management and STIX 2.1 export.
>
> **Stack**: Python · FastAPI · asyncio · httpx · SQLite · SQLModel · NetworkX · React · Docker · GitHub Actions · MITRE ATT&CK · STIX 2.1

---

## Limits (state openly)

- Dark-web visibility comes from aggregators (ransomware.live, Hudson Rock), not direct Tor crawlers
- Canaries validate the pipeline; they do not prove an adversary holds your data
- Real hits for a small organization may be zero — that is a valid result
- Rule precision figures come from a small labeled corpus
