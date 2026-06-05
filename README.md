# LogGenerator_LogDetection

> **ThreatScope** — AI-powered security log evaluation platform with a decoupled dummy server that continuously generates realistic logs and a separate evaluator that runs detection, CVE correlation, AI reasoning, and alert generation.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)
![React](https://img.shields.io/badge/React-18-61dafb)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Overview

ThreatScope simulates a real SOC workflow in a demo environment:

| Application | Role |
|-------------|------|
| **SecureCorp** (dummy website) | Simulates auth, web server, application, firewall, and network layers. Continuously generates logs including attack patterns. |
| **ThreatScope** (log evaluator) | Separate app that ingests logs, detects threats, correlates CVEs, runs AI reasoning, and produces actionable alerts. |

The two apps are **independent** — the dummy site only exposes logs; the evaluator consumes them via a live HTTP feed.

---

## Architecture

```
┌─────────────────────────────────────┐         ┌──────────────────────────────────────┐
│  SecureCorp — Dummy Website         │         │  ThreatScope — Log Evaluator       │
│  :5180 UI  |  :8100 Log API         │  HTTP   │  :5173 UI  |  :8000 API           │
│                                     │ ──────▶ │                                    │
│  • Login / API simulation           │         │  Ingestion + Parsing               │
│  • Continuous log generator         │         │       ↓                            │
│  • Auth / Web / App / FW / Network  │         │  Rule Engine + ML Anomaly Detector │
│  GET /logs/recent                   │         │       ↓                            │
└─────────────────────────────────────┘         │  CVE Correlation (NVD + EPSS)      │
                                                │       ↓                            │
                                                │  Reasoning (Gemini 2.0 Flash)      │
                                                │       ↓                            │
                                                │  Alert Generator + Threat Memory   │
                                                └──────────────────────────────────────┘
```

---

## Features

- **Multi-source log ingestion** — JSON, NDJSON, CSV, Syslog
- **Hybrid detection** — Rule engine (known patterns) + ML Isolation Forest (unknowns)
- **CVE correlation** — Software fingerprinting, NVD API, SQLite cache, EPSS scores
- **AI reasoning layer** — Attack stage, exploitable CVEs, ordered remediation, blast radius (Gemini with fallback)
- **Alert generation** — Severity from CVSS + attack stage, plain-English summaries, line-linked evidence
- **Per-system threat memory** — Each host remembers previously seen malicious patterns
- **Live feed mode** — Fast scan (~seconds) + full analysis (CVE + AI) in background
- **React dashboards** — SecureCorp portal + ThreatScope evaluator UI

---

## Project Structure

```
.
├── dummy-website/              # App 1 — Simulated server + log generator
│   ├── backend/                # FastAPI log API (port 8100)
│   │   ├── generator.py        # Continuous multi-source log generator
│   │   └── main.py
│   └── frontend/               # React portal (port 5180)
├── backend/                    # App 2 — Evaluator API (port 8000)
│   ├── ingestion/              # Log parsing
│   ├── detection/              # Rule engine + ML anomaly detector
│   ├── correlation/            # CVE / NVD / EPSS + SQLite cache
│   ├── reasoning/                # Gemini reasoning layer
│   ├── memory/                 # Per-system threat memory (SQLite)
│   ├── pipeline/               # Orchestrator + alert generator
│   └── main.py
├── app2-threat-dashboard/      # ThreatScope React UI (port 5173)
├── app1-log-generator/         # Standalone static log generator (optional)
├── docs/
│   └── ThreatScope_Problem_Statement.pptx
└── start-all.ps1               # Start all services (Windows)
```

---

## Prerequisites

- **Python 3.11+**
- **Node.js 18+** and npm
- (Optional) **Google API key** for Gemini reasoning — works without it using deterministic fallback

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YaswanthBonthu/LogGenerator_LogDetection.git
cd LogGenerator_LogDetection
```

### 2. Evaluator backend

```bash
cd backend
pip install -r requirements.txt
```

### 3. Dummy website backend

```bash
cd ../dummy-website/backend
pip install -r requirements.txt
```

### 4. Frontend apps

```bash
cd ../../app2-threat-dashboard
npm install

cd ../dummy-website/frontend
npm install
```

---

## Running

### Quick start (Windows)

```powershell
.\start-all.ps1
```

### Manual start

**Terminal 1 — Log generator API**
```bash
cd dummy-website/backend
python -m uvicorn main:app --host 127.0.0.1 --port 8100
```

**Terminal 2 — Evaluator API**
```bash
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

**Terminal 3 — SecureCorp UI**
```bash
cd dummy-website/frontend
npm run dev
```

**Terminal 4 — ThreatScope UI**
```bash
cd app2-threat-dashboard
npm run dev
```

### Service URLs

| Service | URL |
|---------|-----|
| SecureCorp (dummy website) | http://localhost:5180 |
| Log feed API | http://127.0.0.1:8100/logs/recent |
| Evaluator API | http://127.0.0.1:8000 |
| Evaluator API docs | http://127.0.0.1:8000/docs |
| ThreatScope dashboard | http://localhost:5173 |

---

## Usage

### Live demo workflow

1. Open **SecureCorp** at http://localhost:5180 — logs generate continuously in the background.
2. Log in and click **Trigger API Request** to produce more auth/web/app events.
3. Open **ThreatScope** at http://localhost:5173.
4. Click **Connect Live Feed (SecureCorp)**.
5. Dashboard loads in **fast mode** (rule-based scan, seconds).
6. **Full analysis** (CVE + AI reasoning) runs in the background automatically.
7. Explore tabs: Overview, Threats, Memory, Log Stream, CVE Correlation.

### File upload

You can also upload a log file (JSON, NDJSON, CSV, Syslog) directly on the ThreatScope landing page.

### Optional — Gemini AI reasoning

```bash
# Windows PowerShell
$env:GOOGLE_API_KEY = "your-gemini-api-key"

# Linux / macOS
export GOOGLE_API_KEY="your-gemini-api-key"
```

Restart the evaluator API after setting the key. Without it, the system uses a built-in fallback reasoning engine.

---

## API Reference

### Dummy website (`:8100`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health + log buffer stats |
| GET | `/logs/recent?limit=400&since_id=0` | Fetch recent logs (used by evaluator) |
| GET | `/logs/stream` | Server-Sent Events log stream |
| POST | `/api/auth/login` | Simulated login (generates auth logs) |
| GET | `/api/products` | Simulated API (generates web + app logs) |

### Evaluator (`:8000`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | API health check |
| GET | `/analyze/live?mode=fast&limit=400` | Pull logs from dummy site + run pipeline |
| POST | `/analyze/upload` | Upload log file for analysis |
| POST | `/analyze` | Analyze JSON log payload |
| GET | `/memory/systems` | List tracked systems |
| GET | `/memory/threats?system_id=web-01` | Known threats for a host |

**Pipeline modes**

| Mode | Description |
|------|-------------|
| `fast` | Rules only, ~400 logs, instant fallback reasoning — sub-second to few seconds |
| `full` | Rules + ML + CVE (NVD/EPSS) + Gemini reasoning + threat memory |

---

## Detection Pipeline

```
Log Ingestion + Parsing
        ↓
Rule Engine (fast, known patterns)
        +
ML Anomaly Detector (Isolation Forest, unknowns)
        ↓
CVE Correlation Module
  • Extract software + version from logs
  • Query NVD API (cached in SQLite)
  • Enrich with EPSS scores
        ↓
Reasoning Layer (Gemini 2.0 Flash)
  • Input: findings + environment + timeline + CVEs
  • Output: attack stage, exploitable CVEs, remediation, blast radius
        ↓
Alert Generator
  • Severity from CVSS + attack stage + exploitation flag
  • Plain-English summary for stakeholders
  • Evidence with linked log line numbers
```

### Detected attack types

Brute force, SQL injection, XSS, directory traversal, port scan, DDoS, privilege escalation, C2 beacon, behavioral anomalies.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GOOGLE_API_KEY` | — | Gemini API key for AI reasoning |
| `GEMINI_API_KEY` | — | Alternative key name |
| `LOG_SOURCE_URL` | `http://127.0.0.1:8100/logs/recent` | Default live log feed URL |

---

## Tech Stack

| Layer | Technologies |
|-------|--------------|
| Backend | Python, FastAPI, scikit-learn, httpx, SQLite |
| AI | Google Gemini 2.0 Flash |
| CVE data | NVD REST API, FIRST EPSS API |
| Frontend | React 18, Vite, Chart.js |
| Log formats | JSON, NDJSON, CSV, Syslog |

---

## Documentation

- Problem statement deck: [`docs/ThreatScope_Problem_Statement.pptx`](docs/ThreatScope_Problem_Statement.pptx)
- Regenerate PPT: `python docs/create_problem_statement_ppt.py`

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit changes (`git commit -m "Add my feature"`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [NVD](https://nvd.nist.gov/) — National Vulnerability Database
- [FIRST EPSS](https://www.first.org/epss/) — Exploit Prediction Scoring System
- [Google Gemini](https://ai.google.dev/) — AI reasoning layer
