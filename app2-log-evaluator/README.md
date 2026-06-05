# App 2 — Log Evaluator

A FastAPI service that continuously monitors App 1's live log feed, independently
re-derives threats, correlates them with CVEs, and enriches each alert with a
GPT-4o explanation and remediation. Serves a live dashboard.

## Run

```bash
# optional: enable GPT-4o (otherwise a deterministic template fallback is used)
export OPENAI_API_KEY=sk-...

AUTO_MONITOR=1 APP1_URL=http://127.0.0.1:8001 POLL_INTERVAL=2 \
  ./.venv/Scripts/python.exe -m uvicorn main:app --host 127.0.0.1 --port 8002 \
  --app-dir app2-log-evaluator/backend
```

Open http://127.0.0.1:8002 for the dashboard.

| Env var | Default | Purpose |
|---------|---------|---------|
| `APP1_URL` | `http://127.0.0.1:8001` | Log source to poll |
| `POLL_INTERVAL` | `2` | Seconds between polls |
| `AUTO_MONITOR` | `1` | Auto-start the monitor on launch |
| `OPENAI_API_KEY` | — | Enables GPT-4o enrichment |

## Pipeline

1. **monitor.py** — background thread polls `GET {APP1_URL}/api/logs?offset=cursor`
   every `POLL_INTERVAL` seconds and advances the cursor.
2. **detectors.py** — re-derives threats from raw fields (does *not* trust App 1's
   `attack_class`). Stable finding keys make re-analysis idempotent.
3. **cve.py** — correlates a CVE for the component each threat implicates
   (`THREAT_COMPONENT` map). Curated canonical CVEs for the known demo stack;
   live NVD (with word-boundary version matching) + JSON cache for anything else.
4. **llm.py** — `explain(alert)` calls GPT-4o for a JSON `{explanation,
   remediation}`; falls back to a deterministic template when no key is set.
5. **state.py** — rolling event store + de-duplicated alert set; CVE correlation
   and AI enrichment run **once** per new alert.

## API

| Method | Path | Returns |
|--------|------|---------|
| GET | `/api/alerts` | Prioritized, de-duplicated alerts (CVE + AI fields) |
| GET | `/api/insights` | KPIs: event/alert counts by source, severity, threat, top IPs, AI status |
| POST | `/api/ingest` | Push a batch of logs (file/stream import path) |
| POST | `/api/monitor/start` · `/stop` | Control the live monitor |
| GET | `/api/monitor/status` | Monitor state |
| GET | `/api/health` | Health |

## Threat → CVE mapping

| Threat | Component | CVE |
|--------|-----------|-----|
| `path_traversal` | Apache 2.4.49 | CVE-2021-41773 |
| `log4shell` | Log4j2 2.14.1 | CVE-2021-44228 |
| `brute_force(_success)` | OpenSSH 8.1 | CVE-2020-15778 |
| `vulnerable_component` (inventory) | per advertised version | canonical CVE |
| `sql_injection`, `xss`, `idor_enumeration` | app-logic flaw | *(no stack CVE)* |
