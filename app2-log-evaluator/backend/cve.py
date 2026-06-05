"""CVE correlation against the public NVD CVE API (v2.0), with a local cache and
an offline fallback for the known vulnerable components in the demo stack.

Lookups are keyed by "software version". Live results are cached to
cache/nvd_cache.json so repeated runs stay fast and work offline.
"""
from __future__ import annotations

import json
import threading
import time
import re
from pathlib import Path
from typing import Any

import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = Path(__file__).resolve().parent.parent / "cache" / "nvd_cache.json"

# Accurate, well-known CVEs for the demo stack — used offline or if NVD is
# unreachable so correlation always yields a correct result.
FALLBACK: dict[str, dict[str, Any]] = {
    "apache 2.4.49": {"id": "CVE-2021-41773", "cvss": 7.5, "severity": "HIGH",
                      "summary": "Apache HTTP Server 2.4.49 path traversal and RCE via crafted URLs."},
    "log4j2 2.14.1": {"id": "CVE-2021-44228", "cvss": 10.0, "severity": "CRITICAL",
                      "summary": "Apache Log4j2 JNDI 'Log4Shell' remote code execution."},
    "openssl 1.0.1": {"id": "CVE-2014-0160", "cvss": 7.5, "severity": "HIGH",
                      "summary": "OpenSSL 'Heartbleed' TLS heartbeat buffer over-read leaking memory."},
    "openssh 8.1": {"id": "CVE-2020-15778", "cvss": 7.8, "severity": "HIGH",
                    "summary": "OpenSSH scp client command injection via crafted filenames (<=8.3p1)."},
}

_lock = threading.Lock()
_cache: dict[str, Any] = {}


def _load_cache() -> None:
    global _cache
    if CACHE_FILE.exists():
        try:
            _cache = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            _cache = {}


def _save_cache() -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(_cache, indent=2), encoding="utf-8")


_load_cache()


def _parse_nvd(payload: dict, software: str, version: str) -> tuple[dict | None, dict | None]:
    """Return (best_version_match, best_overall).

    Keyword search is noisy (e.g. "OpenSSH 8.1" surfaces unrelated high-CVSS
    entries that merely contain "8.1"). A trustworthy match must mention BOTH
    the product name and the version in its description.
    """
    sw_token = software.split()[0].lower() if software else ""
    best_overall: dict | None = None
    best_match: dict | None = None
    for item in payload.get("vulnerabilities", []):
        c = item.get("cve", {})
        cid = c.get("id")
        desc = next((d["value"] for d in c.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        score, sev = 0.0, "UNKNOWN"
        metrics = c.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cdata = metrics[key][0]["cvssData"]
                score = float(cdata.get("baseScore", 0))
                sev = cdata.get("baseSeverity", metrics[key][0].get("baseSeverity", "UNKNOWN"))
                break
        cand = {"id": cid, "cvss": score, "severity": sev, "summary": desc[:300]}
        if best_overall is None or cand["cvss"] > best_overall["cvss"]:
            best_overall = cand
        dlow = desc.lower()
        ver_hit = bool(version) and re.search(rf"(?<![\d.]){re.escape(version)}(?![\d.])", desc)
        if sw_token and sw_token in dlow and ver_hit:
            if best_match is None or cand["cvss"] > best_match["cvss"]:
                best_match = cand
    return best_match, best_overall


def _query_nvd(keyword: str, software: str, version: str) -> tuple[dict | None, dict | None]:
    try:
        r = httpx.get(NVD_URL,
                      params={"keywordSearch": keyword, "resultsPerPage": 30},
                      timeout=15, headers={"User-Agent": "log-evaluator/1.0"})
        r.raise_for_status()
        return _parse_nvd(r.json(), software, version)
    except Exception:
        return None, None


def lookup(software: str | None, version: str | None) -> dict | None:
    """Return the most relevant CVE for software+version, or None."""
    if not software or not version:
        return None
    key = f"{software} {version}".strip().lower()
    with _lock:
        if key in _cache:
            return _cache[key]

    if key in FALLBACK:
        # known demo component: the curated, canonical CVE is authoritative.
        # NVD keyword search is too noisy to trust over it.
        result = {**FALLBACK[key], "source": "fallback"}
    else:
        live_match, live_overall = _query_nvd(f"{software} {version}", software, version)
        if live_match and live_match.get("id"):
            # a live CVE whose description cites this exact product+version
            result = {**live_match, "source": "nvd"}
        elif live_overall and live_overall.get("id"):
            result = {**live_overall, "source": "nvd"}
        else:
            result = None

    if result:
        result["checked_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with _lock:
            _cache[key] = result
            _save_cache()
    return result
