"""Independent anomaly / threat detection over a window of log events.

Detection does NOT trust any `attack_class` label the source app may attach; it
re-derives threats from raw fields (paths, user-agents, counts, sequences).
Each detector returns findings keyed by a stable signature so the evaluator can
update an existing alert instead of duplicating it.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

SQLI = re.compile(r"('|%27)|(\b(union|select|drop|insert)\b)|(\bor\s+1=1\b)|(;--)|(--\s)", re.I)
XSS = re.compile(r"(<script|onerror=|<img|javascript:)", re.I)
TRAVERSAL = re.compile(r"(\.\./|\.\.%2f|%2e%2e|/etc/passwd|\.%2e)", re.I)
LOG4SHELL = re.compile(r"\$\{jndi:(ldap|rmi|dns)", re.I)
USERS_PATH = re.compile(r"/api/users/(\d+)")

BRUTE_FORCE_THRESHOLD = 10
ENUMERATION_THRESHOLD = 4

# threat type -> (base severity, recommended action)
PLAYBOOK = {
    "brute_force": ("HIGH", "Block the source IP, enable rate limiting / fail2ban, and enforce MFA."),
    "brute_force_success": ("CRITICAL",
        "Treat the account as compromised: rotate credentials, kill active sessions, "
        "block the source IP, and review actions taken after the successful login."),
    "log4shell": ("CRITICAL",
        "Patch Log4j2 to >=2.17.1, set log4j2.formatMsgNoLookups=true, and hunt for "
        "outbound JNDI/LDAP callbacks indicating exploitation."),
    "path_traversal": ("HIGH",
        "Patch the web server, normalize/validate file paths, and restrict filesystem access."),
    "sql_injection": ("HIGH",
        "Use parameterized queries, validate input, and deploy a WAF rule for the source IP."),
    "xss": ("MEDIUM", "Encode output, apply a strict Content-Security-Policy, and sanitize inputs."),
    "idor_enumeration": ("HIGH",
        "Enforce per-object authorization checks and add rate limiting on object access."),
}

# Which stack component a threat actually implicates for CVE correlation.
# Web requests are all logged as "Apache", but Log4Shell is a Log4j2 flaw and
# brute force is an SSH flaw; SQLi/XSS/IDOR are app-logic flaws with no
# stack-component CVE, so they map to None.
THREAT_COMPONENT: dict[str, str | None] = {
    "brute_force": "OpenSSH",
    "brute_force_success": "OpenSSH",
    "log4shell": "Log4j2",
    "path_traversal": "Apache",
    "sql_injection": None,
    "xss": None,
    "idor_enumeration": None,
}

# Canonical versions of the demo stack, used when a component a threat
# implicates has not (yet) appeared in the live inventory window.
DEMO_STACK_VERSION: dict[str, str] = {
    "apache": "2.4.49",
    "log4j2": "2.14.1",
    "openssl": "1.0.1",
    "openssh": "8.1",
}


def _classify_request(path: str, ua: str) -> str | None:
    # Log4Shell payloads usually ride in headers (user-agent); the rest in the path.
    text = f"{path} {ua}"
    if LOG4SHELL.search(text):
        return "log4shell"
    if TRAVERSAL.search(path):
        return "path_traversal"
    if SQLI.search(path):
        return "sql_injection"
    if XSS.search(path):
        return "xss"
    return None


def detect(events: list[dict]) -> list[dict]:
    findings: list[dict] = []
    findings += _detect_brute_force(events)
    findings += _detect_injections(events)
    findings += _detect_enumeration(events)
    return findings


def _sev(threat: str) -> str:
    return PLAYBOOK.get(threat, ("MEDIUM", ""))[0]


def _action(threat: str) -> str:
    return PLAYBOOK.get(threat, ("MEDIUM", "Investigate and contain."))[1]


def _detect_brute_force(events: list[dict]) -> list[dict]:
    fails: dict[tuple, list[dict]] = defaultdict(list)
    successes: dict[tuple, list[dict]] = defaultdict(list)
    for e in events:
        if e.get("event_type") == "auth_failure":
            fails[(e.get("src_ip"), e.get("user"))].append(e)
        elif e.get("event_type") == "auth_success":
            successes[(e.get("src_ip"), e.get("user"))].append(e)

    out = []
    for (ip, user), evs in fails.items():
        if len(evs) < BRUTE_FORCE_THRESHOLD:
            continue
        evs.sort(key=lambda x: x.get("ts") or "")
        first, last = evs[0].get("ts"), evs[-1].get("ts")
        succeeded = (ip, user) in successes and any(
            s["ts"] >= first for s in successes[(ip, user)])
        threat = "brute_force_success" if succeeded else "brute_force"
        sample = evs[0]
        out.append({
            "key": f"bruteforce:{ip}:{user}",
            "threat": threat, "severity": _sev(threat),
            "src_ip": ip, "host": sample.get("host"), "user": user,
            "software": sample.get("software"), "version": sample.get("version"),
            "count": len(evs), "first_ts": first, "last_ts": last,
            "recommended_action": _action(threat),
            "evidence": {"failed_attempts": len(evs),
                         "successful_login_after_burst": succeeded},
        })
    return out


def _detect_injections(events: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for e in events:
        if e.get("event_type") != "web_request":
            continue
        klass = _classify_request(e.get("path", ""), e.get("user_agent", ""))
        if not klass:
            continue
        key = (klass, e.get("src_ip"))
        g = groups.setdefault(key, {"count": 0, "first": e["ts"], "last": e["ts"],
                                    "sample": e["path"], "host": e.get("host"),
                                    "software": e.get("software"), "version": e.get("version")})
        g["count"] += 1
        g["first"] = min(g["first"], e["ts"])
        g["last"] = max(g["last"], e["ts"])

    out = []
    for (klass, ip), g in groups.items():
        out.append({
            "key": f"{klass}:{ip}",
            "threat": klass, "severity": _sev(klass),
            "src_ip": ip, "host": g["host"],
            "software": g["software"], "version": g["version"],
            "count": g["count"], "first_ts": g["first"], "last_ts": g["last"],
            "recommended_action": _action(klass),
            "evidence": {"matched_requests": g["count"], "sample_path": g["sample"]},
        })
    return out


def _detect_enumeration(events: list[dict]) -> list[dict]:
    by_ip: dict[str, set] = defaultdict(set)
    meta: dict[str, dict] = {}
    for e in events:
        if e.get("event_type") != "web_request":
            continue
        m = USERS_PATH.search(e.get("path", ""))
        if not m:
            continue
        ip = e.get("src_ip")
        by_ip[ip].add(m.group(1))
        meta.setdefault(ip, {"first": e["ts"], "last": e["ts"], "host": e.get("host")})
        meta[ip]["first"] = min(meta[ip]["first"], e["ts"])
        meta[ip]["last"] = max(meta[ip]["last"], e["ts"])

    out = []
    for ip, ids in by_ip.items():
        if len(ids) < ENUMERATION_THRESHOLD:
            continue
        out.append({
            "key": f"idor_enumeration:{ip}",
            "threat": "idor_enumeration", "severity": _sev("idor_enumeration"),
            "src_ip": ip, "host": meta[ip]["host"], "software": None, "version": None,
            "count": len(ids), "first_ts": meta[ip]["first"], "last_ts": meta[ip]["last"],
            "recommended_action": _action("idor_enumeration"),
            "evidence": {"distinct_object_ids": sorted(ids, key=int)},
        })
    return out


def extract_inventory(events: list[dict]) -> dict[str, str]:
    """Collect distinct software->version pairs seen in the logs (for CVE scan)."""
    inv: dict[str, str] = {}
    for e in events:
        sw, ver = e.get("software"), e.get("version")
        if sw and ver:
            inv[sw] = ver
    return inv
