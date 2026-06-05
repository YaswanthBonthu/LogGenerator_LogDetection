"""Reasoning layer powered by Gemini with deterministic fallback."""

import json
import os
from typing import List

import google.generativeai as genai

from models.schemas import BlastRadius, CVEEntry, DetectionFinding, EnvironmentContext, ReasoningResult, RemediationStep


class ReasoningLayer:
    def __init__(self, model_name: str = "gemini-2.0-flash"):
        self.model_name = model_name
        api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        self.client = None
        if api_key:
            genai.configure(api_key=api_key)
            self.client = genai.GenerativeModel(model_name)

    async def reason(
        self,
        findings: List[DetectionFinding],
        environment: EnvironmentContext,
        timeline: List[dict],
        cves: List[CVEEntry],
    ) -> ReasoningResult:
        if not findings:
            return self._fallback(findings, environment, timeline, cves)

        if not self.client:
            return self._fallback(findings, environment, timeline, cves)

        prompt = self._build_prompt(findings, environment, timeline, cves)
        try:
            response = await self.client.generate_content_async(prompt)
            text = (response.text or "").strip()
            payload = self._extract_json(text)
            return self._from_payload(payload)
        except Exception:
            return self._fallback(findings, environment, timeline, cves)

    def _build_prompt(self, findings, environment, timeline, cves) -> str:
        return (
            "You are a SOC incident reasoning model. Output STRICT JSON only.\\n"
            "Fields: attack_stage, attack_stage_confidence, kill_chain_phase, exploitable_cves,\\n"
            "remediation_steps (array of {priority, action, rationale, estimated_effort}),\\n"
            "blast_radius ({affected_systems, affected_users, data_at_risk, lateral_movement_risk, scope_summary}),\\n"
            "executive_summary, technical_summary, active_exploitation_likely.\\n"
            "No markdown.\\n\\n"
            f"Findings: {json.dumps([f.model_dump() for f in findings], default=str)[:10000]}\\n"
            f"Environment: {json.dumps(environment.model_dump(), default=str)}\\n"
            f"Timeline: {json.dumps(timeline, default=str)[:4000]}\\n"
            f"CVEs: {json.dumps([c.model_dump() for c in cves], default=str)[:12000]}"
        )

    def _extract_json(self, text: str) -> dict:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("No JSON object found in model response")
        return json.loads(text[start:end + 1])

    def _from_payload(self, p: dict) -> ReasoningResult:
        steps = [RemediationStep(**s) for s in p.get("remediation_steps", [])]
        blast = BlastRadius(**p.get("blast_radius", {}))
        return ReasoningResult(
            attack_stage=p.get("attack_stage", "unknown"),
            attack_stage_confidence=float(p.get("attack_stage_confidence", 0.5)),
            kill_chain_phase=p.get("kill_chain_phase"),
            exploitable_cves=list(p.get("exploitable_cves", [])),
            remediation_steps=steps,
            blast_radius=blast,
            executive_summary=p.get("executive_summary", "Potential security incident detected."),
            technical_summary=p.get("technical_summary", "Refer to findings and evidence."),
            active_exploitation_likely=bool(p.get("active_exploitation_likely", False)),
            model_used=self.model_name,
            fallback_used=False,
        )

    def _fallback(self, findings, environment, timeline, cves) -> ReasoningResult:
        top = max(findings, key=lambda f: f.score) if findings else None
        high_cves = [c for c in cves if (c.cvss_score or 0) >= 8]
        exploitable = [c.cve_id for c in sorted(high_cves, key=lambda x: (x.epss_score or 0), reverse=True)[:8]]

        attack_stage = "Initial Access"
        if top and top.type in {"privilege_escalation", "c2_beacon"}:
            attack_stage = "Privilege Escalation / Command & Control"
        elif top and top.type in {"ddos"}:
            attack_stage = "Impact"

        steps = [
            RemediationStep(priority=1, action="Contain affected hosts and block malicious source IPs.", rationale="Stops ongoing attack traffic and reduces immediate exposure.", estimated_effort="1-2 hours"),
            RemediationStep(priority=2, action="Patch vulnerable software versions identified in CVE correlation.", rationale="Removes known exploit paths tied to observed activity.", estimated_effort="4-24 hours"),
            RemediationStep(priority=3, action="Rotate exposed credentials and enforce MFA on privileged accounts.", rationale="Limits attacker persistence after credential abuse patterns.", estimated_effort="2-6 hours"),
            RemediationStep(priority=4, action="Harden edge controls (WAF/IDS rules, rate limits, segmentation).", rationale="Reduces blast radius and prevents repeat exploitation.", estimated_effort="4-12 hours"),
        ]

        affected_users = sorted({f.affected_user for f in findings if f.affected_user})[:20]
        affected_systems = sorted(set(environment.exposed_services or []))[:20]
        if top and top.source_ip:
            affected_systems = affected_systems or [f"host-contacted-by-{top.source_ip}"]

        blast = BlastRadius(
            affected_systems=affected_systems,
            affected_users=affected_users,
            data_at_risk=["authentication data", "application logs", "service metadata"],
            lateral_movement_risk="high" if top and top.score >= 8 else "medium",
            scope_summary=f"{len(findings)} suspicious detection clusters observed across {len(environment.exposed_services)} exposed services.",
        )

        return ReasoningResult(
            attack_stage=attack_stage,
            attack_stage_confidence=0.68,
            kill_chain_phase=attack_stage,
            exploitable_cves=exploitable,
            remediation_steps=steps,
            blast_radius=blast,
            executive_summary=(
                "We detected suspicious activity that likely represents a real cyber attack attempt. "
                "Immediate containment and targeted patching are recommended to reduce business risk."
            ),
            technical_summary=(
                f"Top finding: {top.title if top else 'N/A'}; "
                f"high-risk CVEs matched: {len(high_cves)}; "
                f"active exploitation likelihood: {'high' if any(c.actively_exploited for c in cves) else 'moderate'}."
            ),
            active_exploitation_likely=any(c.actively_exploited for c in cves) or bool(high_cves),
            model_used=self.model_name,
            fallback_used=True,
        )
