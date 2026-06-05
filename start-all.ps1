# Start all three services: Dummy Website, Evaluator API, ThreatScope Dashboard
$root = $PSScriptRoot

Write-Host "Starting SecureCorp Dummy Server (port 8100)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\dummy-website\backend'; python -m uvicorn main:app --host 127.0.0.1 --port 8100"

Start-Sleep -Seconds 2

Write-Host "Starting ThreatScope Evaluator API (port 8000)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\backend'; python -m uvicorn main:app --host 127.0.0.1 --port 8000"

Start-Sleep -Seconds 2

Write-Host "Starting SecureCorp Frontend (port 5180)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\dummy-website\frontend'; npm run dev"

Start-Sleep -Seconds 2

Write-Host "Starting ThreatScope Dashboard (port 5173)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\app2-threat-dashboard'; npm run dev"

Write-Host ""
Write-Host "Services:" -ForegroundColor Green
Write-Host "  Dummy Website:  http://localhost:5180"
Write-Host "  Log Feed API:   http://127.0.0.1:8100/logs/recent"
Write-Host "  Evaluator API:  http://127.0.0.1:8000"
Write-Host "  ThreatScope UI: http://localhost:5173"
