# How to Run — Copy & Paste Guide

Two apps run side by side:

- **App 1 — Vulnerable Portal** → http://127.0.0.1:8001
- **App 2 — Log Evaluator** → http://127.0.0.1:8002

All commands assume you start from the project root:
`C:\Users\SuraparajuPranavVerm\Desktop\Final_Application`

> Pick the section that matches your terminal: **Git Bash** or **PowerShell**.
> You need **two terminals** — one per app — both left running.

---

## A. One-time setup (install dependencies)

### Git Bash
```bash
cd "/c/Users/SuraparajuPranavVerm/Desktop/Final_Application"
./.venv/Scripts/python.exe -m pip install -r app1-vulnerable-app/backend/requirements.txt
./.venv/Scripts/python.exe -m pip install -r app2-log-evaluator/backend/requirements.txt
```

### PowerShell
```powershell
cd "C:\Users\SuraparajuPranavVerm\Desktop\Final_Application"
.\.venv\Scripts\python.exe -m pip install -r app1-vulnerable-app\backend\requirements.txt
.\.venv\Scripts\python.exe -m pip install -r app2-log-evaluator\backend\requirements.txt
```

---

## B. Terminal 1 — Start App 1 (Vulnerable Portal, port 8001)

### Git Bash
```bash
cd "/c/Users/SuraparajuPranavVerm/Desktop/Final_Application"
./.venv/Scripts/python.exe -m uvicorn main:app --host 127.0.0.1 --port 8001 --app-dir app1-vulnerable-app/backend
```

### PowerShell
```powershell
cd "C:\Users\SuraparajuPranavVerm\Desktop\Final_Application"
.\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8001 --app-dir app1-vulnerable-app\backend
```

Leave this running. Open http://127.0.0.1:8001 in your browser.

---

## C. Terminal 2 — Start App 2 (Log Evaluator, port 8002)

### Git Bash
```bash
cd "/c/Users/SuraparajuPranavVerm/Desktop/Final_Application"
export OPENAI_API_KEY=sk-REPLACE_WITH_YOUR_VALID_KEY
AUTO_MONITOR=1 APP1_URL=http://127.0.0.1:8001 POLL_INTERVAL=2 ./.venv/Scripts/python.exe -m uvicorn main:app --host 127.0.0.1 --port 8002 --app-dir app2-log-evaluator/backend
```

### PowerShell
```powershell
cd "C:\Users\SuraparajuPranavVerm\Desktop\Final_Application"
$env:OPENAI_API_KEY = "sk-REPLACE_WITH_YOUR_VALID_KEY"
$env:AUTO_MONITOR = "1"; $env:APP1_URL = "http://127.0.0.1:8001"; $env:POLL_INTERVAL = "2"
.\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8002 --app-dir app2-log-evaluator\backend
```

Leave this running. Open http://127.0.0.1:8002 in your browser.

> **No OpenAI key?** Skip the `OPENAI_API_KEY` line. The evaluator still runs and
> produces explanations + remediations using a built-in deterministic template;
> the dashboard simply shows `AI: fallback`. Add a valid key and restart this
> terminal to enable GPT-4o — nothing else changes.

---

## D. Generate traffic (so alerts appear)

**Easiest:** on the portal page (http://127.0.0.1:8001) click **Start simulation**.

**Or from a third terminal — Git Bash:**
```bash
curl -s -X POST http://127.0.0.1:8001/api/sim/start -H "Content-Type: application/json" -d '{"duration_sec":8,"rate":5,"brute_force_n":12,"attacks":{"brute_force":true,"sql_injection":true,"path_traversal":true,"log4shell":true,"idor":true}}'
```

**Or from a third terminal — PowerShell:**
```powershell
$body = '{"duration_sec":8,"rate":5,"brute_force_n":12,"attacks":{"brute_force":true,"sql_injection":true,"path_traversal":true,"log4shell":true,"idor":true}}'
Invoke-RestMethod -Uri http://127.0.0.1:8001/api/sim/start -Method Post -ContentType "application/json" -Body $body
```

Within a few seconds the dashboard at http://127.0.0.1:8002 fills with prioritized
alerts, each with a correlated CVE and an explanation + remediation.

---

## E. Quick API checks (optional)

### Git Bash
```bash
curl -s http://127.0.0.1:8001/api/health          # portal + advertised stack
curl -s http://127.0.0.1:8002/api/health          # evaluator
curl -s http://127.0.0.1:8002/api/insights         # KPIs + AI status
curl -s http://127.0.0.1:8002/api/alerts           # full alert list
```

### PowerShell
```powershell
Invoke-RestMethod http://127.0.0.1:8001/api/health
Invoke-RestMethod http://127.0.0.1:8002/api/health
Invoke-RestMethod http://127.0.0.1:8002/api/insights
Invoke-RestMethod http://127.0.0.1:8002/api/alerts
```

---

## F. Stop the apps

Press **Ctrl + C** in each of the two server terminals.

---

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| Dashboard shows `AI: fallback` | No key, or the key was rejected. Set a **valid** `OPENAI_API_KEY` and restart Terminal 2. |
| `401 Incorrect API key` in App 2 logs | The key is revoked/expired/mistyped. Generate a new one at platform.openai.com. |
| No alerts on the dashboard | Generate traffic (step D). Confirm App 2 was started with `APP1_URL=http://127.0.0.1:8001`. |
| `port already in use` | A previous server is still running. Stop it (Ctrl+C) or change the `--port`. |
| CVE shows `source: fallback` | Expected for the 4 known demo components (curated canonical CVEs). Other components use live NVD (`source: nvd`). |
