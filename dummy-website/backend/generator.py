"""Continuous multi-source log generator mimicking auth/web/app/firewall/network."""

import random
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

HOSTS = ["web-01", "web-02", "app-01", "db-01", "fw-01"]
USERS = ["alice", "bob", "charlie", "dave", "eve", "admin", "root"]
SERVICES = {
    "authentication": ("sshd", ["OpenSSH_7.4", "OpenSSH_8.0", "OpenSSH_8.2"]),
    "webserver": ("nginx", ["nginx_1.18.0", "Apache_2.4.41"]),
    "application": ("application", []),
    "firewall": ("firewall", []),
    "network": ("network", []),
}
PATHS = ["/", "/login", "/api/users", "/api/products", "/admin", "/index.html"]
ATTACK_IPS = ["203.0.113.50", "192.0.2.100", "198.51.100.75"]
NORMAL_IPS_PREFIX = ["10.0", "192.168", "172.16"]


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _ip(external: bool = False) -> str:
    if external:
        return random.choice(ATTACK_IPS) if random.random() < 0.15 else (
            f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        )
    p = random.choice(NORMAL_IPS_PREFIX)
    return f"{p}.{random.randint(1,254)}.{random.randint(1,254)}"


class ContinuousLogGenerator:
    """Thread-safe ring buffer with background log production."""

    def __init__(self, max_logs: int = 20000):
        self.max_logs = max_logs
        self._logs: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._seq = 0
        self.attack_rate = 0.12
        self.interval_ms = 400

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        import time
        while self._running:
            batch = random.randint(1, 3)
            for _ in range(batch):
                attack = random.random() < self.attack_rate
                source = random.choice(list(SERVICES.keys()))
                if attack:
                    log = self._attack_log(source)
                else:
                    log = self._normal_log(source)
                self._append(log)
            time.sleep(self.interval_ms / 1000.0)

    def _append(self, log: Dict[str, Any]) -> None:
        with self._lock:
            self._seq += 1
            log["id"] = self._seq
            self._logs.append(log)
            if len(self._logs) > self.max_logs:
                self._logs = self._logs[-self.max_logs:]

    def get_logs(self, since_id: int = 0, limit: int = 500) -> List[Dict[str, Any]]:
        with self._lock:
            if since_id:
                items = [l for l in self._logs if l.get("id", 0) > since_id]
            else:
                items = self._logs[-limit:]
            return list(items[-limit:])

    def get_all(self, limit: int = 5000) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._logs[-limit:])

    def count(self) -> int:
        with self._lock:
            return len(self._logs)

    def latest_id(self) -> int:
        with self._lock:
            return self._logs[-1]["id"] if self._logs else 0

    def record_event(self, event_type: str, **kwargs) -> Dict[str, Any]:
        if event_type == "login":
            log = self._login_event("authentication", **kwargs)
        elif event_type == "http":
            log = self._http_event("webserver", **kwargs)
        elif event_type == "app":
            log = self._app_event("application", **kwargs)
        else:
            log = self._normal_log(event_type, **kwargs)
        self._append(log)
        return log

    def _normal_log(self, source: str, **_) -> Dict[str, Any]:
        host = random.choice(HOSTS)
        if source == "authentication":
            svc, versions = SERVICES[source]
            return {
                "timestamp": _ts(), "host": host, "service": svc,
                "version": random.choice(versions), "event": "authentication",
                "user": random.choice(USERS), "source_ip": _ip(),
                "status": "success", "severity": "INFO",
            }
        if source == "webserver":
            svc, versions = SERVICES[source]
            return {
                "timestamp": _ts(), "host": host, "service": random.choice(["nginx", "Apache"]),
                "version": random.choice(versions), "event": "http_request",
                "method": random.choice(["GET", "POST"]), "path": random.choice(PATHS),
                "status_code": random.choice([200, 201, 204, 404]),
                "source_ip": _ip(), "response_time_ms": random.randint(10, 400),
                "severity": "INFO",
            }
        if source == "application":
            return {
                "timestamp": _ts(), "host": host, "service": "application",
                "event": "log_entry", "level": "INFO",
                "message": random.choice([
                    "Request processed successfully",
                    "Cache hit", "DB query executed", "Session created",
                ]),
                "severity": "INFO",
            }
        if source == "firewall":
            return {
                "timestamp": _ts(), "host": "fw-01", "event": "connection_attempt",
                "source_ip": _ip(), "port": random.randint(1024, 65535),
                "status": random.choice(["allowed", "blocked"]),
                "severity": "INFO" if random.random() > 0.2 else "WARNING",
            }
        return {
            "timestamp": _ts(), "host": host, "event": "network_flow",
            "source_ip": _ip(), "dest_ip": _ip(), "protocol": "TCP",
            "bytes": random.randint(500, 50000), "severity": "INFO",
        }

    def _attack_log(self, source: str) -> Dict[str, Any]:
        attack = random.choice(["brute_force", "sql_injection", "port_scan", "xss"])
        host = random.choice(HOSTS)
        if attack == "brute_force":
            return {
                "timestamp": _ts(), "host": host, "service": "sshd",
                "version": "OpenSSH_7.4", "event": "authentication",
                "user": "root", "source_ip": ATTACK_IPS[0],
                "status": "failed", "reason": "invalid_password",
                "severity": "CRITICAL", "attack_pattern": "brute_force",
            }
        if attack == "sql_injection":
            payloads = [
                "/api/users?id=1' UNION SELECT NULL,NULL,NULL--",
                "/api/users?id=' OR '1'='1",
                "/api/users?id='; DROP TABLE users; --",
            ]
            return {
                "timestamp": _ts(), "host": "web-01", "service": "nginx",
                "version": "nginx_1.18.0", "event": "http_request",
                "method": "GET", "path": random.choice(payloads),
                "status_code": 400, "source_ip": ATTACK_IPS[1],
                "severity": "CRITICAL", "attack_pattern": "sql_injection",
            }
        if attack == "port_scan":
            return {
                "timestamp": _ts(), "host": "db-01", "event": "connection_attempt",
                "source_ip": ATTACK_IPS[2], "dest_port": random.choice([22, 80, 443, 5432, 8080]),
                "protocol": "TCP", "status": "blocked",
                "severity": "HIGH", "attack_pattern": "port_scan",
            }
        return {
            "timestamp": _ts(), "host": "web-02", "service": "Apache",
            "version": "Apache_2.4.41", "event": "http_request",
            "method": "GET", "path": "/?q=<script>alert(1)</script>",
            "status_code": 403, "source_ip": _ip(external=True),
            "severity": "ERROR", "attack_pattern": "xss",
        }

    def _login_event(self, source: str, user: str = "guest", success: bool = True, **_) -> Dict[str, Any]:
        return {
            "timestamp": _ts(), "host": "web-01", "service": "sshd",
            "version": "OpenSSH_8.0", "event": "authentication",
            "user": user, "source_ip": _ip(),
            "status": "success" if success else "failed",
            "reason": None if success else "invalid_password",
            "severity": "INFO" if success else "WARN",
        }

    def _http_event(self, source: str, path: str = "/", method: str = "GET", **_) -> Dict[str, Any]:
        return {
            "timestamp": _ts(), "host": "web-01", "service": "nginx",
            "version": "nginx_1.18.0", "event": "http_request",
            "method": method, "path": path,
            "status_code": 200, "source_ip": _ip(),
            "response_time_ms": random.randint(20, 200), "severity": "INFO",
        }

    def _app_event(self, source: str, message: str = "User action recorded", **_) -> Dict[str, Any]:
        return {
            "timestamp": _ts(), "host": "app-01", "service": "application",
            "event": "log_entry", "level": "INFO", "message": message, "severity": "INFO",
        }
