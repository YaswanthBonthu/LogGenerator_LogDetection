"""FastAPI API for threat analysis pipeline."""

import os
from typing import List, Optional

import httpx
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ingestion import LogParser
from memory import ThreatMemory
from memory.threat_memory import resolve_system_ids
from models.schemas import AnalysisRequest, AnalysisResult, EnvironmentContext, LogEntry, ThreatMemoryEntry
from pipeline import SecurityPipeline

app = FastAPI(title="ThreatScope API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

parser = LogParser()
pipeline = SecurityPipeline()
threat_memory = ThreatMemory()


@app.get("/health")
async def health():
    return {"ok": True, "service": "ThreatScope API"}


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(request: AnalysisRequest):
    if not request.logs:
        raise HTTPException(status_code=400, detail="No logs provided")
    return await pipeline.run(request.logs, request.environment, request.skip_reasoning)


@app.post("/analyze/upload", response_model=AnalysisResult)
async def analyze_upload(
    file: UploadFile = File(...),
    hostname: str = "unknown",
    environment: str = "production",
    os_name: str = "",
):
    content = await file.read()
    try:
        logs = parser.parse_file(content, file.filename or "upload.log")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse log file: {e}")

    hosts = resolve_system_ids(logs, hostname)
    primary = hosts[0] if len(hosts) == 1 else hostname
    env = EnvironmentContext(hostname=primary, environment=environment, os=os_name)
    return await pipeline.run(logs, env, skip_reasoning=False)


@app.get("/memory/systems")
async def list_memory_systems():
    return threat_memory.list_systems()


@app.get("/memory/threats", response_model=list[ThreatMemoryEntry])
async def list_memory_threats(system_id: str | None = None):
    return threat_memory.list_threats(system_id)


@app.post("/parse", response_model=List[LogEntry])
async def parse_only(file: UploadFile = File(...)):
    content = await file.read()
    try:
        return parser.parse_file(content, file.filename or "upload.log")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Parse error: {e}")


DEFAULT_LOG_SOURCE = os.getenv("LOG_SOURCE_URL", "http://127.0.0.1:8100/logs/recent")


class LiveAnalysisRequest(BaseModel):
    source_url: Optional[str] = None
    limit: int = 1000
    since_id: int = 0
    hostname: str = "securecorp"
    environment: str = "production"
    skip_reasoning: bool = False
    mode: str = "fast"  # fast | full


def _pipeline_opts(mode: str, skip_reasoning: bool = False):
    if mode == "full":
        return dict(skip_reasoning=skip_reasoning, skip_cve=False, skip_ml=False, fast_mode=False)
    return dict(skip_reasoning=True, skip_cve=True, skip_ml=True, fast_mode=True)


async def _fetch_logs_from_source(source_url: str, limit: int, since_id: int) -> List[LogEntry]:
    params = {"limit": limit, "since_id": since_id}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(source_url, params=params)
        resp.raise_for_status()
        data = resp.json()
    raw = data.get("logs", data) if isinstance(data, dict) else data
    if not isinstance(raw, list):
        raise HTTPException(status_code=502, detail="Invalid log source response")
    return parser.parse_logs(raw)


@app.get("/analyze/live", response_model=AnalysisResult)
async def analyze_live(
    source_url: str = Query(default=DEFAULT_LOG_SOURCE),
    limit: int = Query(default=400, ge=1, le=10000),
    since_id: int = Query(default=0, ge=0),
    hostname: str = Query(default="securecorp"),
    environment: str = Query(default="production"),
    skip_reasoning: bool = Query(default=False),
    mode: str = Query(default="fast", pattern="^(fast|full)$"),
):
    """Pull logs from dummy website and run pipeline. Use mode=fast for sub-second load."""
    cap = min(limit, 400 if mode == "fast" else 2000)
    try:
        logs = await _fetch_logs_from_source(source_url, cap, since_id)
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch logs: {e}")
    if not logs:
        raise HTTPException(status_code=404, detail="No logs available from source yet")
    hosts = resolve_system_ids(logs, hostname)
    primary = hosts[0] if len(hosts) == 1 else hostname
    env = EnvironmentContext(hostname=primary, environment=environment)
    opts = _pipeline_opts(mode, skip_reasoning)
    result = await pipeline.run(logs, env, **opts)
    result.stats["pipeline_mode"] = mode
    return result


@app.post("/analyze/live", response_model=AnalysisResult)
async def analyze_live_post(request: LiveAnalysisRequest):
    source = request.source_url or DEFAULT_LOG_SOURCE
    try:
        logs = await _fetch_logs_from_source(source, request.limit, request.since_id)
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch logs: {e}")
    if not logs:
        raise HTTPException(status_code=404, detail="No logs available from source yet")
    hosts = resolve_system_ids(logs, request.hostname)
    primary = hosts[0] if len(hosts) == 1 else request.hostname
    env = EnvironmentContext(hostname=primary, environment=request.environment)
    cap = min(request.limit, 400 if request.mode == "fast" else 2000)
    logs = logs[-cap:]
    opts = _pipeline_opts(request.mode, request.skip_reasoning)
    result = await pipeline.run(logs, env, **opts)
    result.stats["pipeline_mode"] = request.mode
    return result
