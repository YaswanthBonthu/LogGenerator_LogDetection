"""Thread-safe append-only log bus for the dummy app.

Every action in the application (real HTTP traffic and simulated traffic alike)
is recorded here. Events get a monotonically increasing `id` used as a cursor so
the Log Evaluator can poll `/api/logs?offset=N` and continuously stream new
events. Events are also persisted to logs/app.log as JSON lines.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import data

LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "app.log"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LogBus:
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(LOG_FILE, "a", encoding="utf-8")

    def emit(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if not event.get("ts"):
                event["ts"] = _now()
            if not event.get("host"):
                event["host"] = data.HOST
            event["id"] = len(self._events)
            self._events.append(event)
            self._fh.write(json.dumps(event) + "\n")
            self._fh.flush()
            return event

    # --- domain helpers shared by HTTP handlers and the simulator ----------

    def auth(self, *, success: bool, user: str, src_ip: str, ts: str | None = None) -> dict:
        ver = data.STACK["OpenSSH"]
        outcome = "Accepted" if success else "Failed"
        return self.emit({
            "ts": ts, "source": "auth",
            "severity": "INFO" if success else "WARNING",
            "event_type": "auth_success" if success else "auth_failure",
            "src_ip": src_ip, "user": user,
            "software": "OpenSSH", "version": ver,
            "message": f"sshd: {outcome} password for {user} from {src_ip} (OpenSSH_{ver})",
        })

    def web(self, *, method: str, path: str, status: int, src_ip: str,
            attack_class: str | None = None, user_agent: str = "Mozilla/5.0",
            ts: str | None = None) -> dict:
        ver = data.STACK["Apache"]
        sev = "INFO" if status < 400 else ("WARNING" if status < 500 else "ERROR")
        if attack_class:
            sev = "ERROR"
        return self.emit({
            "ts": ts, "source": "web",
            "severity": sev, "event_type": "web_request",
            "src_ip": src_ip, "method": method, "path": path, "status": status,
            "software": "Apache", "version": ver, "user_agent": user_agent,
            "attack_class": attack_class,
            "message": (f'{src_ip} - - "{method} {path} HTTP/1.1" {status} '
                        f'"{user_agent}" server=Apache/{ver}'),
        })

    def app_event(self, *, message: str, severity: str = "INFO",
                  software: str | None = None, version: str | None = None,
                  attack_class: str | None = None, src_ip: str | None = None,
                  ts: str | None = None) -> dict:
        return self.emit({
            "ts": ts, "source": "app", "severity": severity,
            "event_type": "app_log", "software": software, "version": version,
            "attack_class": attack_class, "src_ip": src_ip, "message": message,
        })

    # --- read side ---------------------------------------------------------

    def since(self, offset: int) -> list[dict]:
        with self._lock:
            return list(self._events[offset:])

    def count(self) -> int:
        with self._lock:
            return len(self._events)


bus = LogBus()
