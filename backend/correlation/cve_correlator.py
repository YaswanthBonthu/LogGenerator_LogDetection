"""CVE correlation module: software fingerprint extraction + NVD/EPSS enrichment with SQLite cache."""

import json
import os
import re
import sqlite3
import time
from datetime import datetime
from typing import Dict, List, Tuple

import httpx

from models.schemas import CVEEntry, LogEntry, SoftwareFingerprint

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
CACHE_DB = os.path.join(os.path.dirname(__file__), "cve_cache.sqlite")
CACHE_TTL_SECONDS = 60 * 60 * 12

SOFTWARE_PATTERNS: Dict[str, re.Pattern] = {
    "nginx": re.compile(r"nginx[_/\s-]?(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
    "apache": re.compile(r"(?:apache|httpd)[_/\s-]?(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
    "openssh": re.compile(r"openssh[_/\s-]?(?P<version>\d+\.\d+(?:p?\d+)?)", re.I),
    "openssl": re.compile(r"openssl[/\s-]?(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
    "mysql": re.compile(r"mysql[/\s-]?(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
    "postgresql": re.compile(r"postgres(?:ql)?[/\s-]?(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
    "php": re.compile(r"php[/\s-]?(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
    "tomcat": re.compile(r"tomcat[/\s-]?(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
    "django": re.compile(r"django[/\s-]?(?P<version>\d+\.\d+(?:\.\d+)?)", re.I),
}


class CVECorrelator:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._conn = sqlite3.connect(CACHE_DB)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_cache (
              cache_key TEXT PRIMARY KEY,
              fetched_at INTEGER NOT NULL,
              payload TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS epss_cache (
              cve_id TEXT PRIMARY KEY,
              fetched_at INTEGER NOT NULL,
              epss REAL,
              percentile REAL
            )
            """
        )
        self._conn.commit()

    def extract_software(self, logs: List[LogEntry]) -> List[SoftwareFingerprint]:
        findings: Dict[Tuple[str, str], SoftwareFingerprint] = {}
        for idx, log in enumerate(logs):
            text = " ".join([
                log.source or "",
                log.service or "",
                log.message or "",
                json.dumps(log.details or {}),
            ])
            for product, pattern in SOFTWARE_PATTERNS.items():
                m = pattern.search(text)
                if not m:
                    continue
                version = m.groupdict().get("version")
                key = (product, version or "")
                if key not in findings:
                    findings[key] = SoftwareFingerprint(
                        product=product,
                        version=version,
                        source_log_indices=[idx],
                    )
                else:
                    findings[key].source_log_indices.append(idx)

        fallback_products = set(log.service for log in logs if log.service)
        for svc in fallback_products:
            normalized = str(svc).lower()
            if normalized in SOFTWARE_PATTERNS:
                key = (normalized, "")
                if key not in findings:
                    findings[key] = SoftwareFingerprint(product=normalized, version=None, source_log_indices=[])

        return list(findings.values())

    async def correlate(self, fingerprints: List[SoftwareFingerprint]) -> List[CVEEntry]:
        all_cves: Dict[str, CVEEntry] = {}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for fp in fingerprints:
                cves = await self._query_nvd(client, fp)
                for cve in cves:
                    if cve.cve_id not in all_cves:
                        all_cves[cve.cve_id] = cve
                    else:
                        existing = all_cves[cve.cve_id]
                        existing.matched = True
                        if not existing.matched_product:
                            existing.matched_product = fp.product
                        if fp.version and not existing.matched_version:
                            existing.matched_version = fp.version

            await self._enrich_epss(client, list(all_cves.values()))

        return sorted(all_cves.values(), key=lambda x: x.cvss_score or 0, reverse=True)

    async def _query_nvd(self, client: httpx.AsyncClient, fp: SoftwareFingerprint) -> List[CVEEntry]:
        key = f"{fp.product}:{fp.version or ''}"
        cached = self._cache_get(key)
        if cached is not None:
            return self._map_nvd_payload(cached, fp)

        params = {"keywordSearch": fp.product, "resultsPerPage": 20}
        try:
            resp = await client.get(NVD_API, params=params)
            resp.raise_for_status()
            payload = resp.json()
            self._cache_set(key, payload)
            return self._map_nvd_payload(payload, fp)
        except Exception:
            return []

    def _map_nvd_payload(self, payload: dict, fp: SoftwareFingerprint) -> List[CVEEntry]:
        entries: List[CVEEntry] = []
        vulns = payload.get("vulnerabilities", [])
        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            descs = cve.get("descriptions", [])
            description = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
            if fp.product.lower() not in description.lower() and fp.product.lower() not in json.dumps(cve).lower():
                continue

            metrics = cve.get("metrics", {})
            cvss_score = None
            cvss_sev = None
            cvss_vec = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    metric = metrics[key][0]
                    cvss_data = metric.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_sev = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
                    cvss_vec = cvss_data.get("vectorString")
                    break

            refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
            actively_exploited = any(
                tag in (r.get("tags") or [])
                for r in cve.get("references", [])
                for tag in ["Exploit", "Third Party Advisory"]
            )
            entries.append(CVEEntry(
                cve_id=cve_id,
                description=description[:1200],
                cvss_score=float(cvss_score) if cvss_score is not None else None,
                cvss_severity=cvss_sev,
                cvss_vector=cvss_vec,
                published=cve.get("published"),
                last_modified=cve.get("lastModified"),
                references=refs[:8],
                keywords=[fp.product, fp.version] if fp.version else [fp.product],
                matched=True,
                matched_product=fp.product,
                matched_version=fp.version,
                actively_exploited=actively_exploited,
            ))
        return entries

    async def _enrich_epss(self, client: httpx.AsyncClient, cves: List[CVEEntry]) -> None:
        ids = [c.cve_id for c in cves]
        if not ids:
            return
        missing = []
        for cve in cves:
            cached = self._epss_cache_get(cve.cve_id)
            if cached is None:
                missing.append(cve.cve_id)
            else:
                cve.epss_score, cve.epss_percentile = cached

        if not missing:
            return

        try:
            resp = await client.get(EPSS_API, params={"cve": ",".join(missing[:100])})
            resp.raise_for_status()
            data = resp.json().get("data", [])
            by_id = {d.get("cve"): d for d in data}
            for cve in cves:
                d = by_id.get(cve.cve_id)
                if d:
                    cve.epss_score = float(d.get("epss", 0) or 0)
                    cve.epss_percentile = float(d.get("percentile", 0) or 0)
                    self._epss_cache_set(cve.cve_id, cve.epss_score, cve.epss_percentile)
        except Exception:
            return

    def _cache_get(self, key: str):
        cur = self._conn.cursor()
        cur.execute("SELECT fetched_at, payload FROM cve_cache WHERE cache_key = ?", (key,))
        row = cur.fetchone()
        if not row:
            return None
        if int(time.time()) - row["fetched_at"] > CACHE_TTL_SECONDS:
            return None
        return json.loads(row["payload"])

    def _cache_set(self, key: str, payload: dict):
        cur = self._conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO cve_cache(cache_key, fetched_at, payload) VALUES(?, ?, ?)",
            (key, int(time.time()), json.dumps(payload)),
        )
        self._conn.commit()

    def _epss_cache_get(self, cve_id: str):
        cur = self._conn.cursor()
        cur.execute("SELECT fetched_at, epss, percentile FROM epss_cache WHERE cve_id = ?", (cve_id,))
        row = cur.fetchone()
        if not row:
            return None
        if int(time.time()) - row["fetched_at"] > CACHE_TTL_SECONDS:
            return None
        return row["epss"], row["percentile"]

    def _epss_cache_set(self, cve_id: str, epss: float, percentile: float):
        cur = self._conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO epss_cache(cve_id, fetched_at, epss, percentile) VALUES(?, ?, ?, ?)",
            (cve_id, int(time.time()), epss, percentile),
        )
        self._conn.commit()
