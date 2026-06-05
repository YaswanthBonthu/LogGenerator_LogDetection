"""Dummy corporate website backend — continuous log generation API."""

import asyncio
import json
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from generator import ContinuousLogGenerator

app = FastAPI(title="SecureCorp Dummy Server", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HOSTS = ["web-01", "web-02", "app-01", "db-01", "fw-01"]

generator = ContinuousLogGenerator(max_logs=25000)


@app.on_event("startup")
async def startup():
    generator.start()


@app.on_event("shutdown")
async def shutdown():
    generator.stop()


@app.get("/health")
async def health():
    return {
        "ok": True,
        "service": "SecureCorp Dummy Server",
        "logs_buffered": generator.count(),
        "latest_id": generator.latest_id(),
        "generator_running": True,
    }


@app.get("/api/services")
async def services():
    return {
        "authentication": {"status": "online", "host": "web-01", "service": "sshd"},
        "webserver": {"status": "online", "hosts": ["web-01", "web-02"], "stack": "nginx + Apache"},
        "application": {"status": "online", "host": "app-01"},
        "firewall": {"status": "online", "host": "fw-01"},
        "network": {"status": "online", "hosts": HOSTS},
        "log_feed": "/logs/recent",
        "evaluator_hint": "Point ThreatScope to http://127.0.0.1:8100/logs/recent",
    }


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
async def login(req: LoginRequest):
    success = req.password != "wrong" and req.username != ""
    log = generator.record_event("login", user=req.username, success=success)
    if not success:
        log["severity"] = "WARN"
        log["attack_pattern"] = "failed_auth"
    return {
        "success": success,
        "token": "demo-token-abc123" if success else None,
        "log_id": log.get("id"),
    }


@app.get("/api/products")
async def products():
    generator.record_event("http", path="/api/products", method="GET")
    generator.record_event("app", message="Product catalog served")
    return {
        "products": [
            {"id": 1, "name": "Secure Widget", "price": 29.99},
            {"id": 2, "name": "Cloud Shield", "price": 99.00},
        ]
    }


@app.get("/logs/recent")
async def recent_logs(
    limit: int = Query(500, ge=1, le=10000),
    since_id: int = Query(0, ge=0),
    format: str = Query("json", pattern="^(json|ndjson)$"),
):
    logs = generator.get_logs(since_id=since_id, limit=limit)
    if format == "ndjson":
        body = "\n".join(json.dumps(l) for l in logs)
        return StreamingResponse(iter([body]), media_type="application/x-ndjson")
    return {
        "count": len(logs),
        "latest_id": generator.latest_id(),
        "since_id": since_id,
        "logs": logs,
    }


@app.get("/logs/export")
async def export_logs(limit: int = Query(5000, ge=1, le=25000)):
    return {"logs": generator.get_all(limit=limit)}


@app.get("/logs/stream")
async def stream_logs():
    async def event_gen():
        last_id = generator.latest_id()
        yield f"data: {json.dumps({'type': 'connected', 'latest_id': last_id})}\n\n"
        while True:
            await asyncio.sleep(1)
            logs = generator.get_logs(since_id=last_id, limit=100)
            if logs:
                last_id = logs[-1]["id"]
                yield f"data: {json.dumps({'type': 'logs', 'logs': logs})}\n\n"
            else:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream")
