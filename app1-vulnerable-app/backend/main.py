"""App 1 - ACME Portal: a deliberately vulnerable dummy web application.

It offers real, working features (login, product search, profiles, file
download, dashboard) alongside intentional weaknesses: no-rate-limit/
enumerable authentication (brute-forceable), SQL injection, IDOR, path
traversal and a Log4Shell-style sink. Every action is recorded to a log bus
and exposed as a live, cursor-based feed at /api/logs for the Log Evaluator.

WARNING: intentionally insecure. Run only locally for this exercise.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import data
import patterns
from logbus import bus
from simulator import SimConfig, simulator

app = FastAPI(title="ACME Portal (vulnerable dummy app)", version="1.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
# paths excluded from web logging (control/feed plumbing would otherwise be noise)
_NO_LOG = ("/api/logs", "/api/sim", "/healthz", "/favicon.ico")


def client_ip(req: Request) -> str:
    # X-Forwarded-For honored without validation (intentionally spoofable)
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else "0.0.0.0"


@app.middleware("http")
async def log_requests(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if request.url.query:
        path = f"{path}?{request.url.query}"
    if not any(path.startswith(p) for p in _NO_LOG):
        ua = request.headers.get("user-agent", "Mozilla/5.0")
        bus.web(method=request.method, path=path, status=response.status_code,
                src_ip=client_ip(request), user_agent=ua,
                attack_class=patterns.classify(path=path, user_agent=ua))
    return response


# --- application features (with intentional vulnerabilities) ----------------

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def login(body: LoginRequest, request: Request):
    ip = client_ip(request)
    real = data.USERS.get(body.username)
    ok = real is not None and real == body.password
    bus.auth(success=ok, user=body.username, src_ip=ip)
    if ok:
        return {"ok": True, "token": f"session-{body.username}-insecuretoken"}
    # VULN: user enumeration — distinct messages reveal whether the user exists,
    # and there is no rate limiting (brute-forceable).
    msg = "invalid password" if real is not None else "no such user"
    return JSONResponse({"ok": False, "error": msg}, status_code=401)


@app.get("/api/products")
def products(q: str = ""):
    # VULN: query is interpolated into a "SQL" string that gets logged verbatim.
    if q:
        bus.app_event(message=f"executing: SELECT * FROM products WHERE name LIKE '%{q}%'",
                      severity="DEBUG")
    items = [p for p in data.PRODUCTS if q.lower() in p["name"].lower()] if q else data.PRODUCTS
    return {"query": q, "results": items}


@app.get("/api/users/{user_id}")
def get_user(user_id: int):
    # VULN: IDOR — returns any profile with no authorization check.
    return data.PROFILES.get(user_id, {"error": "not found"})


@app.get("/api/files")
def get_file(name: str = "readme.txt"):
    # VULN: path traversal — no sanitization of the requested name.
    if patterns.TRAVERSAL.search(name):
        return PlainTextResponse(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
    return PlainTextResponse(f"contents of {name}: (demo file)")


@app.get("/api/health")
def health():
    return {"status": "ok", "app": "acme-portal", "stack": data.STACK}


# --- live log feed (consumed by the evaluator) ------------------------------

@app.get("/api/logs")
def get_logs(offset: int = 0):
    events = bus.since(offset)
    return {"count": bus.count(), "offset": offset, "next_offset": offset + len(events),
            "events": events}


# --- traffic simulator control ----------------------------------------------

class SimStartRequest(BaseModel):
    duration_sec: int = 60
    rate: int = 20
    attacks: dict[str, bool] | None = None
    brute_force_n: int = 200
    seed: int | None = None


@app.post("/api/sim/start")
def sim_start(body: SimStartRequest) -> dict[str, Any]:
    cfg = SimConfig(
        duration_sec=body.duration_sec, rate=body.rate,
        brute_force_n=body.brute_force_n, seed=body.seed,
        attacks=body.attacks or SimConfig().attacks,
    )
    return simulator.start(cfg)


@app.post("/api/sim/stop")
def sim_stop() -> dict[str, Any]:
    return simulator.stop()


@app.get("/api/sim/status")
def sim_status() -> dict[str, Any]:
    return simulator.status()


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


if FRONTEND.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND), html=True), name="frontend")
