"""GPT-4o explainable alerts.

Given a structured alert (threat, evidence, correlated CVE), produce a concise
human-readable explanation and a recommended remediation. Falls back to a
deterministic template when no OpenAI key is configured or the call fails, so
the evaluator keeps working offline.
"""
from __future__ import annotations

import json
import os
from typing import Any

MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
_AI_ENABLED = bool(os.environ.get("OPENAI_API_KEY"))

_client = None
if _AI_ENABLED:
    try:
        from openai import OpenAI
        # fail fast on a bad key/network so analysis never stalls on retries
        _client = OpenAI(max_retries=0, timeout=15)
    except Exception:
        _AI_ENABLED = False


SYSTEM = (
    "You are a senior SOC security analyst. Given a detected log anomaly and any "
    "correlated CVE, write a short, plain-English alert. Be specific and actionable. "
    "Respond ONLY with JSON: {\"explanation\": str, \"remediation\": str}. "
    "Keep explanation <= 3 sentences and remediation <= 3 sentences."
)


def _fallback(alert: dict[str, Any]) -> dict[str, str]:
    cve = alert.get("cve")
    cve_txt = ""
    if cve:
        cve_txt = (f" Correlated with {cve['id']} (CVSS {cve['cvss']}): "
                   f"{cve.get('summary', '')}".rstrip())
    explanation = (
        f"{alert['threat'].replace('_', ' ').title()} detected from {alert.get('src_ip')} "
        f"on host {alert.get('host')} ({alert.get('count')} related events)."
        + cve_txt)
    return {"explanation": explanation.strip(),
            "remediation": alert.get("recommended_action", "Investigate and contain.")}


def explain(alert: dict[str, Any]) -> dict[str, Any]:
    if not (_AI_ENABLED and _client):
        return {**_fallback(alert), "ai": False}

    context = {
        "threat": alert.get("threat"), "severity": alert.get("severity"),
        "host": alert.get("host"), "src_ip": alert.get("src_ip"),
        "user": alert.get("user"), "software": alert.get("software"),
        "version": alert.get("version"), "count": alert.get("count"),
        "evidence": alert.get("evidence"), "cve": alert.get("cve"),
    }
    try:
        resp = _client.chat.completions.create(
            model=MODEL, temperature=0.2,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": json.dumps(context, default=str)},
            ],
        )
        data = json.loads(resp.choices[0].message.content)
        return {"explanation": data.get("explanation", ""),
                "remediation": data.get("remediation", ""), "ai": True}
    except Exception:  # network / quota / parse — degrade gracefully
        return {**_fallback(alert), "ai": False}


def status() -> dict[str, Any]:
    return {"ai_enabled": bool(_AI_ENABLED and _client), "model": MODEL}
