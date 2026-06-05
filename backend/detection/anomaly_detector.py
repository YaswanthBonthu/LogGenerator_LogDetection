"""ML-based anomaly detection using Isolation Forest on log feature vectors."""

import uuid
from collections import Counter
from typing import List

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from models.schemas import DetectionFinding, LogEntry

SEV_MAP = {"INFO": 0, "WARN": 1, "ERROR": 2, "CRITICAL": 3}
SRC_MAP = {"authentication": 0, "webserver": 1, "application": 2, "firewall": 3, "network": 4}


class MLAnomalyDetector:
    """Detect unknown anomalies via deviation from learned baseline."""

    def __init__(self, contamination: float = 0.08):
        self.contamination = contamination

    def analyze(self, logs: List[LogEntry], rule_indices: set | None = None) -> List[DetectionFinding]:
        if len(logs) < 20:
            return []

        rule_indices = rule_indices or set()
        X = self._extract_features(logs)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        clf = IsolationForest(
            n_estimators=100,
            contamination=min(self.contamination, 0.25),
            random_state=42,
        )
        preds = clf.fit_predict(X_scaled)
        scores = clf.decision_function(X_scaled)

        anomalous_idx = [i for i, p in enumerate(preds) if p == -1 and i not in rule_indices]
        if not anomalous_idx:
            return []

        clusters = self._cluster_by_ip(logs, anomalous_idx)
        findings = []
        for cluster_key, indices in clusters.items():
            cluster_scores = [scores[i] for i in indices]
            avg_dev = float(-np.mean(cluster_scores))
            ml_score = min(10.0, max(3.0, avg_dev * 8 + 2))

            sev = "CRITICAL" if ml_score >= 8 else "HIGH" if ml_score >= 6 else "MEDIUM"
            ip = cluster_key if cluster_key != "_no_ip" else None
            timestamps = sorted(logs[i].timestamp for i in indices)

            dominant_src = Counter(logs[i].source for i in indices).most_common(1)[0][0]
            findings.append(DetectionFinding(
                id=f"ml-{uuid.uuid4().hex[:8]}",
                source="ml",
                type="behavioral_anomaly",
                severity=sev,
                score=round(ml_score, 2),
                title=f"Behavioral Anomaly — {dominant_src}",
                description=(
                    f"ML detector flagged {len(indices)} event(s) deviating from baseline "
                    f"(deviation score: {ml_score:.1f}/10)"
                ),
                source_ip=ip,
                event_count=len(indices),
                first_seen=timestamps[0],
                last_seen=timestamps[-1],
                related_log_indices=indices,
                mitre_tactic="TA0005 Defense Evasion",
            ))
        return sorted(findings, key=lambda f: f.score, reverse=True)

    def _extract_features(self, logs: List[LogEntry]) -> np.ndarray:
        rows = []
        for log in logs:
            msg_len = len(log.message)
            path_depth = log.path.count("/") if log.path else 0
            has_special = int(any(c in log.message for c in "';<>%&|"))
            status = log.status or 200
            rows.append([
                SEV_MAP.get(log.severity, 0),
                SRC_MAP.get(log.source, 5),
                msg_len,
                path_depth,
                has_special,
                status / 100.0,
                log.details.get("attempts", 0) if isinstance(log.details.get("attempts"), (int, float)) else 0,
            ])
        return np.array(rows, dtype=float)

    def _cluster_by_ip(self, logs: List[LogEntry], indices: List[int]) -> dict:
        clusters: dict = {}
        for i in indices:
            ip = logs[i].ip or logs[i].details.get("source_ip") or "_no_ip"
            clusters.setdefault(ip, []).append(i)
        return clusters
