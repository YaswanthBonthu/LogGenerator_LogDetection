"""App 2 - Log Evaluator API.

Continuously monitors App 1's live log feed, detects anomalies/threats,
correlates them with CVEs from NVD, enriches them with GPT-4o explanations and
remedies, and serves a live dashboard. Also accepts pushed log batches at
/api/ingest for the file/stream import path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from monitor import monitor
from state import state

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
APP1_URL = os.environ.get("APP1_URL", "http://127.0.0.1:8001")
AUTO_MONITOR = os.environ.get("AUTO_MONITOR", "1") == "1"


@asynccontextmanager
async def lifespan(app: FastAPI):
    if AUTO_MONITOR:
        monitor.start(APP1_URL, interval=float(os.environ.get("POLL_INTERVAL", "2")))
    yield
    monitor.stop()


app = FastAPI(title="Log Evaluator", version="1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


# --- live monitor control ----------------------------------------------------

class MonitorRequest(BaseModel):
    app1_url: str = APP1_URL
    interval: float = 2.0


@app.post("/api/monitor/start")
def monitor_start(body: MonitorRequest) -> dict[str, Any]:
    return monitor.start(body.app1_url, body.interval)


@app.post("/api/monitor/stop")
def monitor_stop() -> dict[str, Any]:
    return monitor.stop()


@app.get("/api/monitor/status")
def monitor_status() -> dict[str, Any]:
    return monitor.status()


# --- push ingestion (file / stream import path) ------------------------------

class IngestRequest(BaseModel):
    fmt: str = "json"
    data: str | None = None
    events: list[dict] | None = None


@app.post("/api/ingest")
def ingest(body: IngestRequest) -> dict[str, Any]:
    events: list[dict] = []
    if body.events:
        events = body.events
    elif body.data:
        try:
            parsed = json.loads(body.data)
            events = parsed if isinstance(parsed, list) else parsed.get("events", [])
        except json.JSONDecodeError:
            # treat as newline-delimited JSON
            events = [json.loads(line) for line in body.data.splitlines() if line.strip()]
    n = state.add_events(events)
    state.run_analysis()
    return {"ingested": n, "total_events": state.insights()["total_events"]}


# --- read APIs ---------------------------------------------------------------

@app.get("/api/alerts")
def alerts() -> dict[str, Any]:
    return {"alerts": state.alerts_sorted()}


@app.get("/api/insights")
def insights() -> dict[str, Any]:
    return state.insights()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "app": "log-evaluator"}


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


if FRONTEND.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND), html=True), name="frontend")
