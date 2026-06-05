"""Fast rule-based detection for known attack patterns."""

import re
import uuid
from collections import defaultdict
from typing import List

from models.schemas import DetectionFinding, LogEntry


RULES = [
  {
    "id": "R001", "type": "brute_force", "severity": "HIGH", "score": 7.5,
    "title": "SSH Brute Force Attack",
    "pattern": re.compile(r"Failed password for .+ from \d", re.I),
    "mitre": "TA0006 Credential Access",
    "category": "brute_force",
  },
  {
    "id": "R002", "type": "sql_injection", "severity": "CRITICAL", "score": 9.2,
    "title": "SQL Injection Attempt",
    "pattern": re.compile(r"(UNION\s+SELECT|'\s*OR\s*'1'|DROP\s+TABLE|;\s*--|SLEEP\s*\()", re.I),
    "mitre": "TA0001 Initial Access",
    "category": "sql_injection",
  },
  {
    "id": "R003", "type": "xss", "severity": "HIGH", "score": 7.0,
    "title": "Cross-Site Scripting Attempt",
    "pattern": re.compile(r"(<script|onerror\s*=|javascript:|<svg\s+onload)", re.I),
    "mitre": "TA0001 Initial Access",
    "category": "xss",
  },
  {
    "id": "R004", "type": "directory_traversal", "severity": "CRITICAL", "score": 8.8,
    "title": "Directory Traversal Attempt",
    "pattern": re.compile(r"(\.\./|\.\.%2F|%2e%2e|/etc/passwd|/etc/shadow|win\.ini)", re.I),
    "mitre": "TA0007 Discovery",
    "category": "directory_traversal",
  },
  {
    "id": "R005", "type": "port_scan", "severity": "MEDIUM", "score": 5.5,
    "title": "Port Scan Detected",
    "pattern": re.compile(r"(SCAN DETECTED|probing ports|PORT_SCAN|NMAP)", re.I),
    "mitre": "TA0007 Discovery",
    "category": "port_scan",
  },
  {
    "id": "R006", "type": "privilege_escalation", "severity": "CRITICAL", "score": 9.5,
    "title": "Privilege Escalation Attempt",
    "pattern": re.compile(r"(sudo\s+(su|bash|-s)|chmod\s+4755|usermod\s+-aG\s+sudo|pkexec)", re.I),
    "mitre": "TA0004 Privilege Escalation",
    "category": "privilege_escalation",
  },
  {
    "id": "R007", "type": "c2_beacon", "severity": "CRITICAL", "score": 9.8,
    "title": "C2 Beacon / Suspicious Outbound",
    "pattern": re.compile(r"(C2_BEACON|C2_DNS|suspicious domain|telemetry-cdn|update-check\.net)", re.I),
    "mitre": "TA0011 Command and Control",
    "category": "c2_beacon",
  },
  {
    "id": "R008", "type": "ddos", "severity": "CRITICAL", "score": 8.5,
    "title": "DDoS / Traffic Flood",
    "pattern": re.compile(r"(DDOS|Traffic spike|requests_per_sec|exceeds baseline)", re.I),
    "mitre": "TA0040 Impact",
    "category": "ddos",
  },
]


class RuleEngine:
    """Match logs against known attack signatures."""

    def analyze(self, logs: List[LogEntry]) -> List[DetectionFinding]:
        buckets: dict = defaultdict(lambda: {
            "indices": [], "rule": None, "ip": None, "user": None, "timestamps": [],
        })

        for idx, log in enumerate(logs):
            matched_rule = None
            attack_pattern = log.details.get("attack_pattern") or log.category
            if attack_pattern and attack_pattern not in ("normal", "failed_auth", "blocked"):
                for rule in RULES:
                    if rule["category"] == attack_pattern:
                        matched_rule = rule
                        break
            if not matched_rule and log.category and log.category not in ("normal", "failed_auth", "blocked"):
                for rule in RULES:
                    if rule["category"] == log.category:
                        matched_rule = rule
                        break
            if not matched_rule and log.details.get("status") == "failed" and log.details.get("user") == "root":
                for rule in RULES:
                    if rule["category"] == "brute_force":
                        matched_rule = rule
                        break
            if not matched_rule:
                for rule in RULES:
                    if rule["pattern"].search(log.message) or rule["pattern"].search(str(log.details)):
                        matched_rule = rule
                        break
            if not matched_rule:
                continue

            key = (matched_rule["id"], log.ip or log.details.get("source_ip", "unknown"))
            b = buckets[key]
            b["indices"].append(idx)
            b["rule"] = matched_rule
            b["ip"] = log.ip or log.details.get("source_ip")
            b["user"] = log.user
            b["timestamps"].append(log.timestamp)

        findings = []
        for (_, _), b in buckets.items():
            rule = b["rule"]
            ts_sorted = sorted(b["timestamps"])
            findings.append(DetectionFinding(
                id=f"rule-{uuid.uuid4().hex[:8]}",
                source="rule",
                type=rule["type"],
                severity=rule["severity"],
                score=rule["score"],
                title=rule["title"],
                description=f"Rule {rule['id']} matched {len(b['indices'])} log event(s)",
                source_ip=b["ip"],
                affected_user=b["user"],
                event_count=len(b["indices"]),
                first_seen=ts_sorted[0],
                last_seen=ts_sorted[-1],
                related_log_indices=b["indices"],
                mitre_tactic=rule["mitre"],
                rule_id=rule["id"],
            ))
        return sorted(findings, key=lambda f: f.score, reverse=True)
