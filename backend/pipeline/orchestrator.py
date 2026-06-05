"""End-to-end security analysis pipeline orchestrator."""

from collections import Counter
from datetime import datetime
from typing import List

from correlation import CVECorrelator
from detection import MLAnomalyDetector, RuleEngine
from memory import ThreatMemory
from memory.threat_memory import resolve_system_ids
from models.schemas import AnalysisResult, Anomaly, DetectionFinding, EnvironmentContext, LogEntry
from pipeline.alerting import AlertGenerator
from reasoning import ReasoningLayer


class SecurityPipeline:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.ml_detector = MLAnomalyDetector()
        self.cve = CVECorrelator()
        self.reasoning = ReasoningLayer(model_name="gemini-2.0-flash")
        self.alerts = AlertGenerator()
        self.memory = ThreatMemory()

    async def run(
        self,
        logs: List[LogEntry],
        environment: EnvironmentContext,
        skip_reasoning: bool = False,
        skip_cve: bool = False,
        skip_ml: bool = False,
        fast_mode: bool = False,
    ) -> AnalysisResult:
        if not logs:
            return AnalysisResult(
                total_logs=0,
                findings=[],
                anomalies=[],
                software_fingerprints=[],
                cves=[],
                reasoning=None,
                alerts=[],
                stats={"sources": {}, "severities": {}},
                risk_score=0.0,
                timeline=[],
            )

        system_ids = resolve_system_ids(logs, environment.hostname)
        if not fast_mode:
            for sid in system_ids:
                self.memory.register_system(sid, sid, environment.environment)

        rule_findings = self.rule_engine.analyze(logs)
        rule_idxs = {idx for f in rule_findings for idx in f.related_log_indices}
        ml_findings = []
        if not skip_ml and len(logs) >= 20:
            if fast_mode:
                offset = max(0, len(logs) - 400)
                ml_logs = logs[offset:]
                ml_rule_idxs = {i - offset for i in rule_idxs if i >= offset}
            else:
                offset = 0
                ml_logs = logs
                ml_rule_idxs = rule_idxs
            ml_findings = self.ml_detector.analyze(ml_logs, rule_indices=ml_rule_idxs)
            if offset:
                for f in ml_findings:
                    f.related_log_indices = [i + offset for i in f.related_log_indices]
        findings = sorted(rule_findings + ml_findings, key=lambda x: x.score, reverse=True)
        if fast_mode:
            findings = findings[:40]

        memory_hits = []
        if not fast_mode:
            for sid in system_ids:
                scoped = self._logs_for_system(logs, sid, environment.hostname)
                memory_hits.extend(self.memory.scan_logs(sid, scoped))

        for f in findings:
            sys_id, sample = self._finding_context(logs, f, environment.hostname)
            f.system_id = sys_id
            if not fast_mode:
                self.memory.enrich_finding(sys_id, f, sample)

        log_cap = 8 if fast_mode else 25
        anomalies = [
            Anomaly(**f.model_dump(), related_logs=[logs[i].model_dump() for i in f.related_log_indices[:log_cap]], cve_ids=[])
            for f in findings
        ]

        fingerprints = self.cve.extract_software(logs) if not skip_cve else []
        cves = await self.cve.correlate(fingerprints[:3] if fast_mode else fingerprints) if fingerprints else []

        timeline = self._timeline(logs[-500:] if fast_mode else logs, findings)

        if skip_reasoning:
            reasoning = self.reasoning._fallback(findings, environment, timeline, cves)
        else:
            reasoning = await self.reasoning.reason(findings, environment, timeline, cves)

        alerts = self.alerts.generate(findings, logs, cves, reasoning)

        if not fast_mode:
            self.memory.learn_from_analysis(environment.hostname, findings, logs)
        known_threats = []
        memory_stats = {}
        if not fast_mode:
            for sid in system_ids:
                known_threats.extend(self.memory.list_threats(sid))
            memory_stats = self.memory.stats(system_ids)
            memory_stats["known_hits_this_scan"] = len(memory_hits)
            memory_stats["new_findings"] = sum(1 for f in findings if f.memory.is_new)
            memory_stats["recurring_findings"] = sum(1 for f in findings if f.memory.known)
        else:
            memory_stats = {"pipeline_mode": "fast", "deferred": True}

        risk_score = self._risk_score(findings, cves, alerts, memory_hits)

        return AnalysisResult(
            total_logs=len(logs),
            findings=findings,
            anomalies=anomalies,
            software_fingerprints=fingerprints,
            cves=cves,
            reasoning=reasoning,
            alerts=alerts,
            stats=self._stats(logs, findings, cves, memory_stats),
            risk_score=round(risk_score, 2),
            timeline=timeline,
            system_ids=system_ids,
            memory_hits=memory_hits,
            known_threats=known_threats,
            memory_stats=memory_stats,
        )

    @staticmethod
    def _logs_for_system(logs: List[LogEntry], system_id: str, default: str) -> List[LogEntry]:
        return [l for l in logs if (l.details.get("host") or default) == system_id]

    @staticmethod
    def _finding_context(logs: List[LogEntry], finding: DetectionFinding, default: str):
        if not finding.related_log_indices:
            return default, ""
        idx = finding.related_log_indices[0]
        if idx < 0 or idx >= len(logs):
            return default, ""
        log = logs[idx]
        return log.details.get("host") or default, log.message

    def _stats(self, logs: List[LogEntry], findings: List[DetectionFinding], cves, memory_stats=None):
        by_source = Counter(l.source for l in logs)
        by_sev = Counter(l.severity for l in logs)
        finding_types = Counter(f.type for f in findings)
        return {
            "sources": dict(by_source),
            "severities": dict(by_sev),
            "finding_types": dict(finding_types),
            "cve_count": len(cves),
            "high_cve_count": len([c for c in cves if (c.cvss_score or 0) >= 8]),
            "memory": memory_stats or {},
        }

    def _timeline(self, logs: List[LogEntry], findings: List[DetectionFinding]):
        bucket = Counter()
        idx_to_types = {}
        for f in findings:
            for i in f.related_log_indices:
                idx_to_types.setdefault(i, set()).add(f.type)

        for idx, log in enumerate(logs):
            ts = (log.timestamp or "")[:13]
            if not ts:
                continue
            bucket[(ts, "threat" if idx in idx_to_types else "normal")] += 1

        points = []
        for (ts, label), count in sorted(bucket.items(), key=lambda x: x[0][0]):
            points.append({"time": ts, "series": label, "count": count})
        return points

    def _risk_score(self, findings, cves, alerts, memory_hits=None) -> float:
        if not findings and not cves:
            return 0.0
        finding_component = min(10.0, sum(min(10.0, f.score) for f in findings[:8]) / 3)
        cve_component = min(10.0, (max((c.cvss_score or 0) for c in cves) if cves else 0) + (1 if any(c.actively_exploited for c in cves) else 0))
        alert_component = min(10.0, sum(a.severity_score for a in alerts[:5]) / 5) if alerts else 0
        memory_boost = min(1.5, len(memory_hits or []) * 0.05 + sum(1 for f in findings if f.memory.known) * 0.2)
        base = finding_component * 0.45 + cve_component * 0.35 + alert_component * 0.20
        return min(10.0, base + memory_boost)
