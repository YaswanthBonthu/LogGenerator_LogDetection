"""Evaluator state: the rolling event store plus the derived alert set.

Running analysis is idempotent — detectors produce stable keys, so re-running
over a growing event window updates existing alerts instead of duplicating
them. CVE correlation and GPT-4o enrichment happen once per new alert.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

import cve
import detectors
import llm

MAX_EVENTS = 200_000
SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 1}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sev_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _max_sev(a: str, b: str) -> str:
    return a if SEV_ORDER.get(a, 0) >= SEV_ORDER.get(b, 0) else b


class EvalState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.events: list[dict] = []
        self.alerts: dict[str, dict] = {}
        self._alert_seq = 0
        self.last_analysis: str | None = None
        self.monitor = {"running": False, "app1_url": None, "cursor": 0, "interval": 2.0}

    # --- ingestion ---------------------------------------------------------

    def add_events(self, events: list[dict]) -> int:
        with self._lock:
            self.events.extend(events)
            if len(self.events) > MAX_EVENTS:
                self.events = self.events[-MAX_EVENTS:]
            return len(events)

    def snapshot_events(self) -> list[dict]:
        with self._lock:
            return list(self.events)

    # --- analysis ----------------------------------------------------------

    def run_analysis(self) -> None:
        events = self.snapshot_events()
        findings = detectors.detect(events)

        # stack inventory keyed by lowercased software name, so a threat can be
        # correlated against the component it actually implicates.
        inventory = detectors.extract_inventory(events)
        stack = {sw.lower(): (sw, ver) for sw, ver in inventory.items()}

        for f in findings:
            comp = detectors.THREAT_COMPONENT.get(f["threat"], "__self__")
            if comp is None:
                sw, ver = None, None  # app-logic flaw: no stack-component CVE
            elif comp == "__self__":
                sw, ver = f.get("software"), f.get("version")
            else:
                sw, ver = stack.get(
                    comp.lower(),
                    (comp, detectors.DEMO_STACK_VERSION.get(comp.lower())))
            self._upsert(f, software=sw, version=ver)

        # inventory-based CVE scan: flag vulnerable components even without a
        # behavioral trigger (e.g. Heartbleed via the advertised OpenSSL version)
        for sw, ver in detectors.extract_inventory(events).items():
            key = f"vulnerable_component:{sw}:{ver}"
            if key in self.alerts:
                continue
            match = cve.lookup(sw, ver)
            if not match:
                continue
            self._upsert({
                "key": key, "threat": "vulnerable_component",
                "severity": _sev_from_cvss(match.get("cvss", 0)),
                "src_ip": None, "host": None, "software": sw, "version": ver,
                "count": 1, "first_ts": _now(), "last_ts": _now(),
                "recommended_action": f"Upgrade {sw} {ver} to a fixed release.",
                "evidence": {"detected_via": "software inventory in logs"},
            }, software=sw, version=ver, known_cve=match)

        with self._lock:
            self.last_analysis = _now()

    def _upsert(self, f: dict, software: str | None, version: str | None,
                known_cve: dict | None = None) -> None:
        key = f["key"]
        with self._lock:
            existing = self.alerts.get(key)

        if existing:
            with self._lock:
                existing["count"] = f.get("count", existing["count"])
                existing["last_ts"] = f.get("last_ts", existing["last_ts"])
                existing["evidence"] = f.get("evidence", existing["evidence"])
                existing["updated_ts"] = _now()
            return

        # new alert: correlate CVE (once) then enrich with GPT-4o (once)
        match = known_cve if known_cve is not None else cve.lookup(software, version)
        severity = f["severity"]
        if match:
            severity = _max_sev(severity, _sev_from_cvss(match.get("cvss", 0)))

        alert = {
            "key": key, "threat": f["threat"], "severity": severity,
            "title": self._title(f, match),
            "host": f.get("host"), "src_ip": f.get("src_ip"), "user": f.get("user"),
            "software": software, "version": version,
            "count": f.get("count", 1),
            "first_ts": f.get("first_ts"), "last_ts": f.get("last_ts"),
            "evidence": f.get("evidence", {}),
            "recommended_action": f.get("recommended_action", ""),
            "cve": match,
        }
        enrichment = llm.explain(alert)
        alert["ai_explanation"] = enrichment["explanation"]
        alert["ai_remediation"] = enrichment["remediation"]
        alert["ai"] = enrichment.get("ai", False)

        with self._lock:
            self._alert_seq += 1
            alert["id"] = self._alert_seq
            alert["created_ts"] = _now()
            alert["updated_ts"] = alert["created_ts"]
            self.alerts[key] = alert

    @staticmethod
    def _title(f: dict, match: dict | None) -> str:
        name = f["threat"].replace("_", " ").title()
        host = f.get("host") or "stack"
        base = f"{name} on {host}"
        if f.get("src_ip"):
            base += f" from {f['src_ip']}"
        if match:
            base += f" — matches {match['id']} (CVSS {match['cvss']})"
        return base

    # --- read side ---------------------------------------------------------

    def alerts_sorted(self) -> list[dict]:
        with self._lock:
            items = list(self.alerts.values())
        items.sort(key=lambda a: (SEV_ORDER.get(a["severity"], 0), a["last_ts"] or ""),
                   reverse=True)
        return items

    def insights(self) -> dict[str, Any]:
        with self._lock:
            events = self.events
            alerts = list(self.alerts.values())
            by_source: dict[str, int] = {}
            by_severity: dict[str, int] = {}
            ip_counts: dict[str, int] = {}
            for e in events:
                by_source[e.get("source", "?")] = by_source.get(e.get("source", "?"), 0) + 1
                by_severity[e.get("severity", "?")] = by_severity.get(e.get("severity", "?"), 0) + 1
                ip = e.get("src_ip")
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            alert_sev: dict[str, int] = {}
            alert_threat: dict[str, int] = {}
            for a in alerts:
                alert_sev[a["severity"]] = alert_sev.get(a["severity"], 0) + 1
                alert_threat[a["threat"]] = alert_threat.get(a["threat"], 0) + 1
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:8]
            cursor = self.monitor["cursor"]
            running = self.monitor["running"]
            last = self.last_analysis

        return {
            "total_events": len(events),
            "events_by_source": by_source,
            "events_by_severity": by_severity,
            "total_alerts": len(alerts),
            "alerts_by_severity": alert_sev,
            "alerts_by_threat": alert_threat,
            "top_source_ips": [{"ip": ip, "events": n} for ip, n in top_ips],
            "monitor_running": running,
            "cursor": cursor,
            "last_analysis": last,
            "ai": llm.status(),
        }


state = EvalState()
