# App 1 — Vulnerable Portal ("ACME Portal")

A real, working FastAPI web application with intentionally exploitable
vulnerabilities. Every action — legitimate or malicious — is written to a
live, append-only log feed that App 2 (the Log Evaluator) consumes.

> ⚠️ This app is deliberately insecure. Run it only on `127.0.0.1` for the demo.
> Never expose it to a network.

## Run

```bash
./.venv/Scripts/python.exe -m uvicorn main:app --host 127.0.0.1 --port 8001 \
  --app-dir app1-vulnerable-app/backend
```

Open http://127.0.0.1:8001 for the portal UI and live log tail.

## Endpoints

| Method | Path | Behaviour | Intentional flaw |
|--------|------|-----------|------------------|
| POST | `/api/login` | Authenticates a user | Username enumeration + **no rate limiting** → brute force |
| GET | `/api/products?q=` | Product search | **SQL injection** (logs the raw query as if concatenated) |
| GET | `/api/users/{id}` | Fetch a profile | **IDOR** — no authorization, sequential ids leak SSN/salary |
| GET | `/api/files?name=` | Read a "document" | **Path traversal** — returns fake `/etc/passwd` |
| GET | `/api/health` | Health + advertised stack | Leaks outdated component versions |
| GET | `/api/logs?offset=N` | **Cursor-based live log feed** consumed by App 2 | — |
| POST | `/api/sim/start` · `/stop` | Drive the traffic simulator | — |
| GET | `/api/sim/status` | Simulator status | — |

`Log4Shell` is exercised via a `${jndi:ldap://…}` payload carried in the
`User-Agent` header of web requests.

## Logging

`logbus.py` is a thread-safe, append-only bus. Each event gets a monotonic `id`
used as the streaming cursor and is also persisted to `logs/app.log` as JSON
lines. Domain helpers emit structured events:

- `auth(...)` → OpenSSH 8.1 `auth_success` / `auth_failure`
- `web(...)` → Apache 2.4.49 `web_request`
- `app_event(...)` → application logs (carry Log4j2 / OpenSSL inventory)

Each event includes `ts`, `src_ip`, `software`, `version`, `path`, `status`,
`user_agent`, and a human-readable `message`.

## Simulator

`simulator.py` runs in a background thread and emits a mix of normal traffic and
configurable attack bursts (brute force, SQLi, path traversal, Log4Shell, IDOR)
from distinct attacker IPs, so App 2 has realistic, labelled-by-behaviour data
to analyse.
