# DarkWeb Watchdog — Platform Specification

## Overview

DarkWeb Watchdog (DWW) is a canary-validated external exposure intelligence platform. It continuously monitors public data sources for mentions of your organization's assets — domains, emails, IPs, vendors — and provides scored, triaged findings with case management, graph analysis, and export capabilities.

## Architecture

### Data Flow

```
Sources → Collectors → Pipeline (Normalize + Redact + Dedup) → Rules Engine → Scorer → Findings DB
                                                                                          ↓
                                                              Canary Tracker ←→ Graph Builder
                                                                                          ↓
                                                              Cases → Audit Log → Notifications → Exports
```

### Components

#### Collectors (M1)
- **github_gist** — Monitor public GitHub Gists for credential dumps
- **github_code** — Code search for domain/email references
- **github_events** — Real-time GitHub public event stream
- **crt_sh** — Certificate Transparency log monitor (lookalike domains)
- **ransomware_live** — Ransomware.live victim tracker
- **hudson_rock** — Hudson Rock infostealer exposure API
- **otx_pulses** — AlienVault OTX threat intelligence pulses
- **threatfox** — Abuse.ch ThreatFox IOC feed
- **abuseipdb** — AbuseIPDB reputation checks

#### Pipeline
- **Normalize** — Common schema, fingerprinting
- **Redact** — Privacy-by-design secret redaction with salted hashing
- **Dedup** — SHA-256 fingerprint-based deduplication

#### Rules Engine
Detection-as-code rules in YAML (Sigma-inspired). Each rule has:
- `id` — Unique rule identifier (DWW-CATEGORY-NNN)
- `detection` — Selection criteria (regex, wordlist, canary_marker) + condition
- `applies_to` — Source filter list
- `severity_base` — Base score (0-100)
- `confidence_base` — Base confidence (0.0-1.0)
- `attack` — ATT&CK technique IDs
- `playbook` — Response playbook reference

#### Scoring
Multi-factor scoring (max 100):
- `category_base` — Rule severity base (0-80)
- `plaintext_secret` — +15 if secret was visible in plaintext
- `domain_match` — +10 if watched domain matched
- `freshness` — +10 (≤24h), +5 (≤7d), +0 (older)
- `blast_radius` — +0-20 based on graph connectivity
- `sightings` — +2 per additional sighting, max +10

Severity bands: critical (≥80), high (≥60), medium (≥35), low (<35)

#### Case Management
- Findings are grouped into Cases
- SLA timers: critical (1h ack, 4h contain), high (4h/24h), medium (24h/72h), low (72h/168h)
- Tamper-evident audit chain: each audit log entry hashes previous entry

#### Canary System
- Plant unique CNRY-XXXXXXXX markers in GitHub Gists, TLS certificates
- Detect when markers appear in monitored feeds → confirmed data exfiltration
- Track time-to-detect metrics

#### Graph
- Assets and findings as nodes
- Edges: asset→finding (mentioned_in), asset→asset (related_to)
- Blast radius = criticality-weighted neighbor count within N hops

## Data Models

### Asset
- id, type (domain/subdomain/ip/email_pattern/vendor/person), value, criticality (1-5), owner, created_at

### RawItem
- id, source, url, fetched_at, fingerprint, redacted_text, data_origin (live/replay/canary)

### Finding
- id, raw_item_id, rule_id, category, severity, confidence, score, score_breakdown (JSON)
- asset_id, first_seen, last_seen, sightings, status, title, description, attack_techniques (JSON)

### Case
- id, title, status, severity, sla_ack_due, sla_contain_due, created_at, updated_at, assignee

### Canary
- id, type, marker, location_url, planted_at, first_detected_at, detected_source, time_to_detect_seconds

### AuditLog
- id, ts, actor, action, detail (JSON), prev_hash, hash (SHA-256 chain)

## API

RESTful FastAPI application. All endpoints return JSON.
Server-Sent Events (SSE) stream at `/stream/findings` for real-time updates.

## Security

- All secrets redacted before database storage
- Salted SHA-256 fingerprinting for deduplication
- Tamper-evident audit log
- API key authentication (M2)
- Data retention policy (configurable, default 30 days)

## Privacy

- No raw credentials stored — only redacted versions with hash fingerprints
- Canary markers are synthetic and contain no real credentials
- Replay mode allows safe re-processing of historical data without live API calls

## Threat Intelligence Sources

| Source | Type | Free Tier |
|---|---|---|
| GitHub public API | Gists, code search, events | Yes (rate limited) |
| crt.sh | Certificate Transparency | Yes |
| Ransomware.live | Victim tracker | Yes |
| Hudson Rock | Infostealer exposure | Yes (limited) |
| AlienVault OTX | Threat pulses | Yes |
| ThreatFox (Abuse.ch) | IOC feed | Yes |
| AbuseIPDB | IP reputation | Yes |

## ATT&CK Coverage

Rules map to MITRE ATT&CK techniques:
- T1078 — Valid Accounts
- T1195 — Supply Chain Compromise
- T1486 — Data Encrypted for Impact (ransomware)
- T1552.001 — Credentials in Files
- T1555.003 — Credentials from Web Browsers
- T1566 — Phishing
- T1583.001 — Acquire Infrastructure: Domains
- T1589.001 — Gather Victim Identity Information: Credentials
- T1593.003 — Search Open Technical Databases
- T1596 — Search Open Technical Databases

## Deployment

- Docker + Docker Compose (single container for M0-M2)
- SQLite database (upgradeable to PostgreSQL in M3+)
- GitHub Actions CI pipeline
