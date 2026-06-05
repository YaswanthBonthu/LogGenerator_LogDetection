"""Alert generation from findings + reasoning + correlated CVEs."""

import uuid
from datetime import datetime
from typing import List

from models.schemas import Alert, CVEEntry, DetectionFinding, EvidenceItem, LogEntry, ReasoningResult


SEV_WEIGHT = {"LOW": 2, "MEDIUM": 4, "HIGH": 7, "CRITICAL": 9}
STAGE_WEIGHT = {
    "Reconnaissance": 1,
    "Initial Access": 2,
    "Execution": 3,
    "Persistence": 4,
    "Privilege Escalation / Command & Control": 5,
    "Impact": 6,
}


class AlertGenerator:
    def generate(
        self,
        findings: List[DetectionFinding],
        logs: List[LogEntry],
        cves: List[CVEEntry],
        reasoning: ReasoningResult,
    ) -> List[Alert]:
        alerts: List[Alert] = []
        cves_by_id = {c.cve_id: c for c in cves}

        for finding in findings:
            related = [c for c in cves if c.matched and (c.cvss_score or 0) >= 6]
            evidence = self._collect_evidence(logs, finding.related_log_indices)
            active_flag = reasoning.active_exploitation_likely or any(c.actively_exploited for c in related)
            sev_score = self._severity_score(finding, reasoning.attack_stage, related, active_flag)
            sev_label = self._severity_label(sev_score)

            known = finding.memory.known
            summary = (
                f"{finding.title} was detected with {finding.event_count} related log event(s). "
                f"The incident is assessed at the '{reasoning.attack_stage}' attack stage and requires immediate containment."
            )
            if known:
                summary += (
                    f" This system recognizes this as a previously seen threat "
                    f"(first observed {finding.memory.first_seen[:10] if finding.memory.first_seen else 'earlier'}, "
                    f"{finding.memory.occurrence_count} total occurrence(s) on {finding.system_id or 'this host'})."
                )
            if active_flag:
                summary += " Evidence suggests active exploitation is likely."

            if known:
                sev_score = min(10.0, sev_score + 0.7)

            alerts.append(Alert(
                id=f"alert-{uuid.uuid4().hex[:10]}",
                severity=self._severity_label(sev_score),
                severity_score=round(sev_score, 2),
                title=finding.title,
                summary=summary,
                technical_detail=f"{finding.description}. MITRE: {finding.mitre_tactic or 'n/a'}.",
                attack_stage=reasoning.attack_stage,
                active_exploitation=active_flag,
                known_threat=known,
                memory_occurrences=finding.memory.occurrence_count,
                memory_first_seen=finding.memory.first_seen,
                system_id=finding.system_id,
                remediation=reasoning.remediation_steps,
                blast_radius=reasoning.blast_radius,
                evidence=evidence,
                related_cves=related[:8],
                finding_ids=[finding.id],
                created_at=datetime.utcnow().isoformat() + "Z",
            ))

        alerts.sort(key=lambda a: a.severity_score, reverse=True)
        return alerts

    def _collect_evidence(self, logs: List[LogEntry], indices: List[int]) -> List[EvidenceItem]:
        items = []
        for i in indices[:25]:
            if i < 0 or i >= len(logs):
                continue
            log = logs[i]
            items.append(EvidenceItem(
                line_number=log.line_number or (i + 1),
                timestamp=log.timestamp,
                source=log.source,
                severity=log.severity,
                message=log.message,
                category=log.category,
            ))
        return items

    def _severity_score(self, finding, attack_stage: str, cves: List[CVEEntry], active_flag: bool) -> float:
        finding_weight = finding.score
        stage_weight = STAGE_WEIGHT.get(attack_stage, 3)
        max_cvss = max((c.cvss_score or 0) for c in cves) if cves else 0
        epss_boost = max((c.epss_score or 0) for c in cves) * 2 if cves else 0
        active_boost = 1.5 if active_flag else 0
        return min(10.0, finding_weight * 0.5 + stage_weight + max_cvss * 0.2 + epss_boost + active_boost)

    def _severity_label(self, score: float) -> str:
        if score >= 8.5:
            return "CRITICAL"
        if score >= 6.5:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
