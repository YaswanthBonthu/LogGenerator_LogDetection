"""Per-system threat memory — recognizes previously seen malicious patterns."""

import hashlib
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from models.schemas import DetectionFinding, LogEntry, ThreatMemoryEntry, ThreatMemoryInfo, KnownLogHit

DB_PATH = os.path.join(os.path.dirname(__file__), "threat_memory.sqlite")

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
NUM_RE = re.compile(r"\b\d+\b")


def _normalize_message(msg: str) -> str:
    s = msg.lower().strip()
    s = IP_RE.sub("<IP>", s)
    s = TS_RE.sub("<TS>", s)
    s = NUM_RE.sub("<N>", s)
    return s


def _log_fingerprint(log: LogEntry) -> str:
    attack = log.details.get("attack_pattern") or log.category or ""
    payload = "|".join([
        log.source,
        str(attack),
        _normalize_message(log.message),
        str(log.path or ""),
    ])
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _threat_key(threat_type: str, source_ip: Optional[str]) -> str:
    return f"{threat_type}:{source_ip or 'any'}"


class ThreatMemory:
    """SQLite-backed memory store scoped per system (hostname)."""

    def __init__(self, db_path: str = DB_PATH):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        cur = self._conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS systems (
                system_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                environment TEXT DEFAULT 'production',
                registered_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS threat_records (
                id TEXT PRIMARY KEY,
                system_id TEXT NOT NULL,
                threat_key TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                source_ip TEXT,
                title TEXT,
                severity TEXT,
                mitre_tactic TEXT,
                sample_message TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                occurrence_count INTEGER DEFAULT 1,
                UNIQUE(system_id, threat_key),
                FOREIGN KEY (system_id) REFERENCES systems(system_id)
            );
            CREATE TABLE IF NOT EXISTS log_records (
                id TEXT PRIMARY KEY,
                system_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                category TEXT,
                source_ip TEXT,
                sample_message TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                hit_count INTEGER DEFAULT 1,
                UNIQUE(system_id, fingerprint),
                FOREIGN KEY (system_id) REFERENCES systems(system_id)
            );
            CREATE INDEX IF NOT EXISTS idx_threat_system ON threat_records(system_id);
            CREATE INDEX IF NOT EXISTS idx_log_fp ON log_records(system_id, fingerprint);
        """)
        self._conn.commit()

    def register_system(self, system_id: str, hostname: str, environment: str = "production") -> None:
        now = datetime.utcnow().isoformat() + "Z"
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO systems(system_id, hostname, environment, registered_at, last_seen_at)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(system_id) DO UPDATE SET last_seen_at=excluded.last_seen_at
            """,
            (system_id, hostname, environment, now, now),
        )
        self._conn.commit()

    def lookup_threat(self, system_id: str, threat_type: str, source_ip: Optional[str]) -> Optional[Dict[str, Any]]:
        key = _threat_key(threat_type, source_ip)
        cur = self._conn.cursor()
        cur.execute(
            "SELECT * FROM threat_records WHERE system_id=? AND threat_key=?",
            (system_id, key),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def lookup_log(self, system_id: str, log: LogEntry) -> Optional[Dict[str, Any]]:
        fp = _log_fingerprint(log)
        cur = self._conn.cursor()
        cur.execute(
            "SELECT * FROM log_records WHERE system_id=? AND fingerprint=?",
            (system_id, fp),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def remember_threat(
        self,
        system_id: str,
        finding: DetectionFinding,
        sample_message: str = "",
    ) -> ThreatMemoryInfo:
        key = _threat_key(finding.type, finding.source_ip)
        now = datetime.utcnow().isoformat() + "Z"
        existing = self.lookup_threat(system_id, finding.type, finding.source_ip)

        cur = self._conn.cursor()
        if existing:
            count = existing["occurrence_count"] + finding.event_count
            cur.execute(
                """
                UPDATE threat_records
                SET last_seen=?, occurrence_count=?, sample_message=COALESCE(?, sample_message)
                WHERE id=?
                """,
                (finding.last_seen or now, count, sample_message or None, existing["id"]),
            )
            self._conn.commit()
            return ThreatMemoryInfo(
                known=True,
                memory_id=existing["id"],
                occurrence_count=count,
                first_seen=existing["first_seen"],
                last_seen=finding.last_seen or now,
                is_new=False,
            )

        mem_id = f"mem-{uuid.uuid4().hex[:10]}"
        cur.execute(
            """
            INSERT INTO threat_records(
                id, system_id, threat_key, threat_type, source_ip, title, severity,
                mitre_tactic, sample_message, first_seen, last_seen, occurrence_count
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                mem_id, system_id, key, finding.type, finding.source_ip,
                finding.title, finding.severity, finding.mitre_tactic,
                sample_message[:500], finding.first_seen or now, finding.last_seen or now,
                finding.event_count,
            ),
        )
        self._conn.commit()
        return ThreatMemoryInfo(
            known=False,
            memory_id=mem_id,
            occurrence_count=finding.event_count,
            first_seen=finding.first_seen or now,
            last_seen=finding.last_seen or now,
            is_new=True,
        )

    def remember_log(self, system_id: str, log: LogEntry, threat_type: str) -> None:
        fp = _log_fingerprint(log)
        now = log.timestamp or datetime.utcnow().isoformat() + "Z"
        cur = self._conn.cursor()
        cur.execute(
            "SELECT id, hit_count FROM log_records WHERE system_id=? AND fingerprint=?",
            (system_id, fp),
        )
        row = cur.fetchone()
        if row:
            cur.execute(
                "UPDATE log_records SET last_seen=?, hit_count=hit_count+1 WHERE id=?",
                (now, row["id"]),
            )
        else:
            cur.execute(
                """
                INSERT INTO log_records(
                    id, system_id, fingerprint, threat_type, category, source_ip,
                    sample_message, first_seen, last_seen, hit_count
                ) VALUES(?,?,?,?,?,?,?,?,?,1)
                """,
                (
                    f"log-{uuid.uuid4().hex[:10]}", system_id, fp, threat_type,
                    log.category, log.ip or log.details.get("source_ip"),
                    log.message[:500], now, now,
                ),
            )
        self._conn.commit()

    def scan_logs(self, system_id: str, logs: List[LogEntry]) -> List[KnownLogHit]:
        hits: List[KnownLogHit] = []
        for log in logs:
            if log.category in ("normal", "failed_auth", "blocked") and not log.details.get("attack_pattern"):
                continue
            rec = self.lookup_log(system_id, log)
            if not rec:
                continue
            hits.append(KnownLogHit(
                line_number=log.line_number or 0,
                message=log.message,
                threat_type=rec["threat_type"],
                source_ip=rec["source_ip"],
                system_id=system_id,
                occurrence_count=rec["hit_count"],
                first_seen=rec["first_seen"],
                last_seen=rec["last_seen"],
                fingerprint=rec["fingerprint"],
            ))
        return hits

    def enrich_finding(
        self,
        system_id: str,
        finding: DetectionFinding,
        sample_message: str,
    ) -> DetectionFinding:
        existing = self.lookup_threat(system_id, finding.type, finding.source_ip)
        if existing:
            finding.memory = ThreatMemoryInfo(
                known=True,
                memory_id=existing["id"],
                occurrence_count=existing["occurrence_count"],
                first_seen=existing["first_seen"],
                last_seen=existing["last_seen"],
                is_new=False,
            )
            finding.score = min(10.0, finding.score + 0.8)
            finding.description += (
                f" [KNOWN THREAT — seen {existing['occurrence_count']} time(s) on this system since {existing['first_seen'][:10]}]"
            )
        else:
            finding.memory = ThreatMemoryInfo(known=False, is_new=True)
        return finding

    def learn_from_analysis(
        self,
        system_id: str,
        findings: List[DetectionFinding],
        logs: List[LogEntry],
    ) -> Tuple[int, int]:
        self.register_system(system_id, system_id)
        new_threats = 0
        updated = 0
        for f in findings:
            sample = ""
            if f.related_log_indices:
                idx = f.related_log_indices[0]
                if 0 <= idx < len(logs):
                    sample = logs[idx].message
                    sys_id = logs[idx].details.get("host") or system_id
                    self.remember_log(sys_id, logs[idx], f.type)
            sys_id = system_id
            if f.related_log_indices and f.related_log_indices[0] < len(logs):
                sys_id = logs[f.related_log_indices[0]].details.get("host") or system_id
            self.register_system(sys_id, sys_id)
            info = self.remember_threat(sys_id, f, sample)
            if info.is_new:
                new_threats += 1
            else:
                updated += 1
            for idx in f.related_log_indices[:10]:
                if 0 <= idx < len(logs):
                    host = logs[idx].details.get("host") or system_id
                    self.remember_log(host, logs[idx], f.type)
        return new_threats, updated

    def list_threats(self, system_id: Optional[str] = None) -> List[ThreatMemoryEntry]:
        cur = self._conn.cursor()
        if system_id:
            cur.execute(
                "SELECT * FROM threat_records WHERE system_id=? ORDER BY last_seen DESC",
                (system_id,),
            )
        else:
            cur.execute("SELECT * FROM threat_records ORDER BY last_seen DESC LIMIT 200")
        return [
            ThreatMemoryEntry(
                id=r["id"],
                system_id=r["system_id"],
                threat_type=r["threat_type"],
                source_ip=r["source_ip"],
                title=r["title"] or r["threat_type"],
                severity=r["severity"] or "MEDIUM",
                sample_message=r["sample_message"] or "",
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                occurrence_count=r["occurrence_count"],
                mitre_tactic=r["mitre_tactic"],
            )
            for r in cur.fetchall()
        ]

    def list_systems(self) -> List[Dict[str, Any]]:
        cur = self._conn.cursor()
        cur.execute("""
            SELECT s.system_id, s.hostname, s.environment, s.last_seen_at,
                   COUNT(t.id) as threat_count
            FROM systems s
            LEFT JOIN threat_records t ON t.system_id = s.system_id
            GROUP BY s.system_id
            ORDER BY s.last_seen_at DESC
        """)
        return [dict(r) for r in cur.fetchall()]

    def stats(self, system_ids: List[str]) -> Dict[str, Any]:
        threats = self.list_threats()
        scoped = [t for t in threats if t.system_id in system_ids] if system_ids else threats
        return {
            "systems_tracked": len(system_ids) or len(self.list_systems()),
            "total_known_threats": len(scoped),
            "by_type": _count_by(scoped, "threat_type"),
            "by_system": _count_by(scoped, "system_id"),
        }


def _count_by(items, attr: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in items:
        key = getattr(item, attr)
        out[key] = out.get(key, 0) + 1
    return out


def resolve_system_ids(logs: List[LogEntry], default_hostname: str) -> List[str]:
    hosts = {log.details.get("host") for log in logs if log.details.get("host")}
    if not hosts:
        return [default_hostname]
    return sorted(hosts)
