from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime


# ─── Log Generator (existing) ───────────────────────────────────────────────

class AttackConfig(BaseModel):
    enabled: bool = False
    intensity: int = 5


class SeverityMix(BaseModel):
    info: float = 60
    warn: float = 25
    error: float = 10
    critical: float = 5


class GenerateRequest(BaseModel):
    volume: int = 500
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    sources: List[str] = ["authentication", "webserver", "application", "firewall", "network"]
    severity_mix: SeverityMix = SeverityMix()
    anomaly_ratio: float = 20.0
    attacks: Dict[str, AttackConfig] = {}


class LogEntry(BaseModel):
    timestamp: str
    source: str
    severity: str
    category: str
    ip: Optional[str] = None
    user: Optional[str] = None
    service: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    message: str
    details: Dict[str, Any] = {}
    line_number: Optional[int] = None


# ─── Detection ──────────────────────────────────────────────────────────────

class ThreatMemoryInfo(BaseModel):
    known: bool = False
    memory_id: Optional[str] = None
    occurrence_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    is_new: bool = True


class KnownLogHit(BaseModel):
    line_number: int
    message: str
    threat_type: str
    source_ip: Optional[str] = None
    system_id: str
    occurrence_count: int = 1
    first_seen: str
    last_seen: str
    fingerprint: Optional[str] = None


class ThreatMemoryEntry(BaseModel):
    id: str
    system_id: str
    threat_type: str
    source_ip: Optional[str] = None
    title: str
    severity: str
    sample_message: str = ""
    first_seen: str
    last_seen: str
    occurrence_count: int = 1
    mitre_tactic: Optional[str] = None


class DetectionFinding(BaseModel):
    id: str
    source: Literal["rule", "ml"] = "rule"
    type: str
    severity: str
    score: float
    title: str
    description: str
    source_ip: Optional[str] = None
    affected_user: Optional[str] = None
    event_count: int = 1
    first_seen: str
    last_seen: str
    related_log_indices: List[int] = []
    mitre_tactic: Optional[str] = None
    rule_id: Optional[str] = None
    system_id: Optional[str] = None
    memory: ThreatMemoryInfo = ThreatMemoryInfo()


class Anomaly(DetectionFinding):
    related_logs: List[Dict[str, Any]] = []
    cve_ids: List[str] = []


# ─── CVE ────────────────────────────────────────────────────────────────────

class SoftwareFingerprint(BaseModel):
    product: str
    vendor: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    source_log_indices: List[int] = []


class CVEEntry(BaseModel):
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    published: Optional[str] = None
    last_modified: Optional[str] = None
    references: List[str] = []
    keywords: List[str] = []
    matched: bool = False
    matched_product: Optional[str] = None
    matched_version: Optional[str] = None
    actively_exploited: bool = False


# ─── Reasoning Layer ────────────────────────────────────────────────────────

class RemediationStep(BaseModel):
    priority: int
    action: str
    rationale: str
    estimated_effort: Optional[str] = None


class BlastRadius(BaseModel):
    affected_systems: List[str] = []
    affected_users: List[str] = []
    data_at_risk: List[str] = []
    lateral_movement_risk: str = "unknown"
    scope_summary: str = ""


class ReasoningResult(BaseModel):
    attack_stage: str
    attack_stage_confidence: float = 0.0
    kill_chain_phase: Optional[str] = None
    exploitable_cves: List[str] = []
    remediation_steps: List[RemediationStep] = []
    blast_radius: BlastRadius = BlastRadius()
    executive_summary: str = ""
    technical_summary: str = ""
    active_exploitation_likely: bool = False
    model_used: str = "gemini-2.0-flash"
    fallback_used: bool = False


# ─── Alerts ─────────────────────────────────────────────────────────────────

class EvidenceItem(BaseModel):
    line_number: int
    timestamp: str
    source: str
    severity: str
    message: str
    category: Optional[str] = None


class Alert(BaseModel):
    id: str
    severity: str
    severity_score: float
    title: str
    summary: str
    technical_detail: str
    attack_stage: str
    active_exploitation: bool = False
    known_threat: bool = False
    memory_occurrences: int = 0
    memory_first_seen: Optional[str] = None
    system_id: Optional[str] = None
    remediation: List[RemediationStep] = []
    blast_radius: BlastRadius = BlastRadius()
    evidence: List[EvidenceItem] = []
    related_cves: List[CVEEntry] = []
    finding_ids: List[str] = []
    created_at: str


# ─── Pipeline ───────────────────────────────────────────────────────────────

class EnvironmentContext(BaseModel):
    hostname: str = "unknown"
    environment: str = "production"
    os: Optional[str] = None
    exposed_services: List[str] = []
    critical_assets: List[str] = []


class AnalysisRequest(BaseModel):
    logs: Optional[List[LogEntry]] = None
    environment: EnvironmentContext = EnvironmentContext()
    skip_reasoning: bool = False


class AnalysisResult(BaseModel):
    total_logs: int
    findings: List[DetectionFinding]
    anomalies: List[Anomaly]
    software_fingerprints: List[SoftwareFingerprint]
    cves: List[CVEEntry]
    reasoning: Optional[ReasoningResult] = None
    alerts: List[Alert] = []
    stats: Dict[str, Any]
    risk_score: float
    timeline: List[Dict[str, Any]] = []
    system_ids: List[str] = []
    memory_hits: List[KnownLogHit] = []
    known_threats: List[ThreatMemoryEntry] = []
    memory_stats: Dict[str, Any] = {}
