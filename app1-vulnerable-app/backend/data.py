"""Seed data and tech-stack metadata for the ACME Portal dummy application.

The component versions below are real and intentionally vulnerable so that the
Log Evaluator's NVD correlation produces meaningful, well-known CVE matches.
"""

HOST = "portal-01"

# Intentionally vulnerable tech stack (component -> version). These map to:
#   Apache 2.4.49   -> CVE-2021-41773 (path traversal, CVSS 7.5)
#   Log4j2 2.14.1   -> CVE-2021-44228 "Log4Shell" (RCE, CVSS 10.0)
#   OpenSSL 1.0.1   -> CVE-2014-0160 "Heartbleed" (info leak, CVSS 7.5)
#   OpenSSH 8.1     -> brute-force surface for the SSH-backed login
STACK = {
    "Apache": "2.4.49",
    "Log4j2": "2.14.1",
    "OpenSSL": "1.0.1",
    "OpenSSH": "8.1",
}

# username -> password (plaintext on purpose: this is the vulnerable app)
USERS = {
    "admin": "admin123",
    "deploy": "Deploy!2023",
    "jdoe": "password1",
    "svc_app": "s3rvice",
    "ubuntu": "ubuntu",
}

# IDOR target: any caller can read any profile by id (no auth check)
PROFILES = {
    1: {"id": 1, "user": "admin", "role": "superuser", "ssn": "***-**-1001", "salary": 185000},
    2: {"id": 2, "user": "deploy", "role": "ci", "ssn": "***-**-1002", "salary": 142000},
    3: {"id": 3, "user": "jdoe", "role": "employee", "ssn": "***-**-1003", "salary": 96000},
    4: {"id": 4, "user": "svc_app", "role": "service", "ssn": "***-**-1004", "salary": 0},
    5: {"id": 5, "user": "ubuntu", "role": "employee", "ssn": "***-**-1005", "salary": 88000},
}

PRODUCTS = [
    {"id": 101, "name": "Widget", "price": 19.99},
    {"id": 102, "name": "Gadget", "price": 34.50},
    {"id": 103, "name": "Sprocket", "price": 7.25},
    {"id": 104, "name": "Cog", "price": 12.00},
    {"id": 105, "name": "Flux Capacitor", "price": 999.99},
]

NORMAL_USERS_IPS = [f"10.0.{n // 254}.{(n % 254) + 1}" for n in range(1, 40)]
NORMAL_PATHS = ["/", "/dashboard", "/api/products", "/api/health",
                "/static/app.js", "/api/products?q=widget", "/api/products?q=cog"]
