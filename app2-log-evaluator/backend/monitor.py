"""Continuous monitor.

Polls App 1's live, cursor-based log feed (`/api/logs?offset=N`) in a background
thread, appends new events to the evaluator state and re-runs analysis. This is
what makes the evaluator a live monitor rather than a one-shot batch tool.
"""
from __future__ import annotations

import threading
import time

import httpx

from state import state


class Monitor:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self, app1_url: str, interval: float = 2.0) -> dict:
        if self._thread and self._thread.is_alive():
            return {"running": True, "note": "already running", "app1_url": state.monitor["app1_url"]}
        self._stop.clear()
        state.monitor.update({"running": True, "app1_url": app1_url.rstrip("/"),
                              "interval": interval, "cursor": 0})
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return {"running": True, "app1_url": state.monitor["app1_url"], "interval": interval}

    def stop(self) -> dict:
        self._stop.set()
        state.monitor["running"] = False
        return {"running": False}

    def status(self) -> dict:
        running = bool(self._thread and self._thread.is_alive())
        state.monitor["running"] = running
        return dict(state.monitor)

    def _run(self) -> None:
        url = state.monitor["app1_url"] + "/api/logs"
        interval = state.monitor["interval"]
        while not self._stop.is_set():
            cursor = state.monitor["cursor"]
            try:
                r = httpx.get(url, params={"offset": cursor}, timeout=10)
                r.raise_for_status()
                payload = r.json()
                events = payload.get("events", [])
                if events:
                    state.add_events(events)
                    state.monitor["cursor"] = payload.get("next_offset", cursor + len(events))
                    state.run_analysis()
            except Exception:
                pass  # App 1 may not be up yet; retry next tick
            time.sleep(interval)
        state.monitor["running"] = False


monitor = Monitor()
