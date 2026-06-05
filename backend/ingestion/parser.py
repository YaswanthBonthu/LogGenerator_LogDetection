"""Log ingestion and parsing for JSON, CSV, and syslog formats."""

import csv
import io
import json
import re
from typing import List, Union

from models.schemas import LogEntry


SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d+)>\d*\s+(?P<ts>[\d\-T:.Z+]+)\s+"
    r"(?P<host>\S+)\s+(?P<svc>\S+)\s+.*?\s+(?P<msg>.+)$"
)
SEVERITY_FROM_PRI = {0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "ERROR", 4: "WARN", 6: "INFO"}


class LogParser:
    """Parse raw log files into normalized LogEntry objects."""

    def parse_file(self, content: bytes, filename: str) -> List[LogEntry]:
        text = content.decode("utf-8", errors="replace")
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        stripped = text.strip()

        if ext == "json" or stripped.startswith("[") or stripped.startswith("{"):
            return self._parse_json(text)
        if ext == "csv":
            return self._parse_csv(text)
        return self._parse_syslog(text)

    def parse_logs(self, raw: List[dict]) -> List[LogEntry]:
        return [self._dict_to_entry(d, i + 1) for i, d in enumerate(raw)]

    def _parse_json(self, text: str) -> List[LogEntry]:
        stripped = text.strip()
        if stripped.startswith("{"):
            # NDJSON: one JSON object per line
            entries = []
            for i, line in enumerate(text.splitlines(), start=1):
                line = line.strip()
                if not line:
                    continue
                entries.append(self._dict_to_entry(json.loads(line), i))
            if entries:
                return entries

        data = json.loads(text)
        if isinstance(data, dict) and "logs" in data:
            data = data["logs"]
        if not isinstance(data, list):
            raise ValueError("JSON must be an array of log objects or NDJSON lines")
        return [self._dict_to_entry(d, i + 1) for i, d in enumerate(data)]

    def _parse_csv(self, text: str) -> List[LogEntry]:
        reader = csv.DictReader(io.StringIO(text))
        entries = []
        for i, row in enumerate(reader, start=1):
            entries.append(LogEntry(
                timestamp=row.get("timestamp", ""),
                source=row.get("source", "unknown"),
                severity=row.get("severity", "INFO").upper(),
                category=row.get("category", "normal"),
                ip=row.get("ip") or None,
                user=row.get("user") or None,
                message=row.get("message", ""),
                line_number=i,
            ))
        return entries

    def _parse_syslog(self, text: str) -> List[LogEntry]:
        entries = []
        for i, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            m = SYSLOG_RE.match(line)
            if m:
                pri = int(m.group("pri")) % 8
                entries.append(LogEntry(
                    timestamp=m.group("ts"),
                    source=m.group("svc"),
                    severity=SEVERITY_FROM_PRI.get(pri, "INFO"),
                    category="normal",
                    ip=m.group("host") if self._looks_like_ip(m.group("host")) else None,
                    service=m.group("svc"),
                    message=m.group("msg"),
                    line_number=i,
                ))
            else:
                entries.append(LogEntry(
                    timestamp="",
                    source="syslog",
                    severity="INFO",
                    category="normal",
                    message=line,
                    line_number=i,
                ))
        return entries

    def _dict_to_entry(self, d: dict, line_number: int) -> LogEntry:
        known = {"timestamp", "source", "severity", "category", "ip", "user",
                 "service", "method", "path", "status", "message", "details", "line_number"}
        details = dict(d.get("details") or {})
        for k, v in d.items():
            if k not in known and v is not None:
                details[k] = v

        event = str(d.get("event", "")).lower()
        source_map = {
            "authentication": "authentication",
            "http_request": "webserver",
            "connection_attempt": "firewall",
            "log_entry": "application",
        }
        source = d.get("source") or source_map.get(event, event or "unknown")
        category = d.get("category") or d.get("attack_pattern") or "normal"
        if category == "normal" and d.get("status") == "failed" and event == "authentication":
            category = "failed_auth"
        if category == "normal" and d.get("status") == "blocked":
            category = "blocked"

        severity = str(d.get("severity", "INFO")).upper()
        if severity == "WARNING":
            severity = "WARN"

        ip = d.get("ip") or d.get("source_ip") or d.get("src_ip")
        status = d.get("status") if isinstance(d.get("status"), str) else d.get("status_code")
        message = d.get("message")
        if not message:
            parts = [event or source]
            if d.get("user"):
                parts.append(f"user={d['user']}")
            if ip:
                parts.append(f"from {ip}")
            if d.get("path"):
                parts.append(f"path={d['path']}")
            if d.get("method"):
                parts.append(f"method={d['method']}")
            if d.get("status") or d.get("status_code"):
                parts.append(f"status={d.get('status') or d.get('status_code')}")
            if d.get("reason"):
                parts.append(f"reason={d['reason']}")
            if d.get("version"):
                parts.append(f"version={d['version']}")
            message = " ".join(parts)

        return LogEntry(
            timestamp=str(d.get("timestamp", "")),
            source=str(source),
            severity=severity,
            category=str(category),
            ip=ip,
            user=d.get("user"),
            service=d.get("service"),
            method=d.get("method"),
            path=d.get("path"),
            status=status if isinstance(status, int) else None,
            message=str(message),
            details=details,
            line_number=d.get("line_number", line_number),
        )

    @staticmethod
    def _looks_like_ip(s: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))
