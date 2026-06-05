"""Traffic simulator.

Drives the dummy application with a configurable mix of normal user activity and
attack patterns, all emitted through the same log bus the real HTTP handlers use.
Runs in a background thread so the Log Evaluator sees a continuous, live stream.
"""
from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import data
import patterns
from logbus import bus


def _ext_ip(rng: random.Random) -> str:
    return f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


@dataclass
class SimConfig:
    duration_sec: int = 60          # how long to run
    rate: int = 20                  # normal events per tick (~1s)
    attacks: dict[str, bool] = field(default_factory=lambda: {
        "brute_force": True, "sql_injection": True,
        "path_traversal": True, "log4shell": True, "idor": True,
    })
    brute_force_n: int = 200        # failed attempts per brute-force incident
    seed: int | None = None


class Simulator:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._state: dict[str, Any] = {"running": False, "emitted": 0, "config": None}

    # --- public control ----------------------------------------------------

    def start(self, cfg: SimConfig) -> dict:
        if self._thread and self._thread.is_alive():
            return {"running": True, "note": "already running", **self.status()}
        self._stop.clear()
        self._state = {"running": True, "emitted": 0,
                       "config": cfg.__dict__, "started_ts": time.time()}
        self._thread = threading.Thread(target=self._run, args=(cfg,), daemon=True)
        self._thread.start()
        return self.status()

    def stop(self) -> dict:
        self._stop.set()
        return self.status()

    def status(self) -> dict:
        running = bool(self._thread and self._thread.is_alive())
        self._state["running"] = running
        self._state["total_logged"] = bus.count()
        return dict(self._state)

    # --- worker ------------------------------------------------------------

    def _run(self, cfg: SimConfig) -> None:
        rng = random.Random(cfg.seed)
        bus.app_event(
            message=("ACME Portal 1.0 starting "
                     f"(Apache/{data.STACK['Apache']}, Log4j2 {data.STACK['Log4j2']}, "
                     f"OpenSSL {data.STACK['OpenSSL']}, OpenSSH_{data.STACK['OpenSSH']})"),
            software="ACME-Portal", version="1.0",
        )
        ticks = max(1, cfg.duration_sec)
        brute_at = rng.randint(0, ticks - 1) if cfg.attacks.get("brute_force") else -1

        for t in range(ticks):
            if self._stop.is_set():
                break
            self._normal_batch(rng, cfg.rate)
            self._maybe_attacks(rng, cfg, fire_brute=(t == brute_at))
            self._state["emitted"] = bus.count()
            time.sleep(1.0)

        self._state["running"] = False

    # --- activity emitters -------------------------------------------------

    def _normal_batch(self, rng: random.Random, rate: int) -> None:
        for _ in range(max(0, rate)):
            roll = rng.random()
            ip = rng.choice(data.NORMAL_USERS_IPS)
            if roll < 0.25:
                bus.auth(success=True, user=rng.choice(list(data.USERS)), src_ip=ip)
            elif roll < 0.85:
                bus.web(method="GET", path=rng.choice(data.NORMAL_PATHS),
                        status=rng.choices([200, 200, 304, 404], weights=[6, 3, 1, 1])[0],
                        src_ip=ip)
            else:
                bus.app_event(message=rng.choice([
                    "request handled in 42ms", "cache hit user=jdoe",
                    "db query ok rows=12", "session created"]),
                    severity=rng.choices(["INFO", "DEBUG", "WARNING"], weights=[6, 2, 1])[0])

    def _maybe_attacks(self, rng: random.Random, cfg: SimConfig, fire_brute: bool) -> None:
        a = cfg.attacks
        if fire_brute and a.get("brute_force"):
            self._brute_force(rng, cfg.brute_force_n)
        if a.get("sql_injection") and rng.random() < 0.3:
            self._injection(rng, "sql")
        if a.get("path_traversal") and rng.random() < 0.3:
            self._injection(rng, "traversal")
        if a.get("log4shell") and rng.random() < 0.2:
            self._injection(rng, "log4shell")
        if a.get("idor") and rng.random() < 0.25:
            self._idor(rng)

    def _brute_force(self, rng: random.Random, n: int) -> None:
        attacker = _ext_ip(rng)
        user = rng.choice(["root", "admin"])
        for _ in range(n):
            bus.auth(success=False, user=user, src_ip=attacker)
        bus.auth(success=True, user=user, src_ip=attacker)  # the dangerous success

    def _injection(self, rng: random.Random, kind: str) -> None:
        attacker = _ext_ip(rng)
        if kind == "sql":
            q = rng.choice(patterns.SQLI_QUERIES)
            path = f"/api/products?q={q}"
            ua = "sqlmap/1.6"
        elif kind == "traversal":
            path = f"/api/files?name={rng.choice(patterns.TRAVERSAL_FILES)}"
            ua = "curl/8.0"
        else:  # log4shell
            path = "/api/products?q=shoes"
            ua = rng.choice(patterns.LOG4SHELL_UAS)
        klass = patterns.classify(path=path, user_agent=ua)
        bus.web(method="GET", path=path, status=rng.choice([200, 403, 500]),
                src_ip=attacker, attack_class=klass, user_agent=ua)
        if klass == "log4shell":
            bus.app_event(message=f"Log4j2 lookup evaluated for UA from {attacker}: {ua}",
                          severity="ERROR", software="Log4j2",
                          version=data.STACK["Log4j2"], attack_class="log4shell",
                          src_ip=attacker)

    def _idor(self, rng: random.Random) -> None:
        attacker = _ext_ip(rng)
        for pid in range(1, rng.randint(4, 6)):  # sequential profile enumeration
            bus.web(method="GET", path=f"/api/users/{pid}", status=200,
                    src_ip=attacker, attack_class="idor", user_agent="python-requests/2.31")


simulator = Simulator()
