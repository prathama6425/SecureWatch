"""
SOC Lab Configuration
======================
Central configuration for the Mini SOC Lab backend.
"""

import os

# ── Base Paths ────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH  = os.path.join(BASE_DIR, "soc_lab.db")

# ── Flask ─────────────────────────────────────────────────────────────────────
SECRET_KEY  = "soc-lab-secret-2026"
DEBUG       = True
HOST        = "0.0.0.0"
PORT        = 5000

# ── IOC Feed paths ────────────────────────────────────────────────────────────
IOC_IPS_FILE     = os.path.join(DATA_DIR, "ioc_feeds", "malicious_ips.json")
IOC_DOMAINS_FILE = os.path.join(DATA_DIR, "ioc_feeds", "malicious_domains.json")

# ── Detection Thresholds ──────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD  = 5   # failed logins in window
BRUTE_FORCE_WINDOW     = 60  # seconds
PORT_SCAN_THRESHOLD    = 15  # distinct ports from one IP
SUSPICIOUS_HOUR_START  = 22  # 10 PM
SUSPICIOUS_HOUR_END    = 6   # 6 AM

# ── Severity Levels ───────────────────────────────────────────────────────────
SEVERITY = {
    "LOW":      1,
    "MEDIUM":   2,
    "HIGH":     3,
    "CRITICAL": 4,
}

# ── MITRE ATT&CK Tactic Mapping ───────────────────────────────────────────────
MITRE_TACTICS = {
    "brute_force":       {"tactic": "Credential Access",   "technique": "T1110"},
    "port_scan":         {"tactic": "Discovery",            "technique": "T1046"},
    "suspicious_login":  {"tactic": "Initial Access",       "technique": "T1078"},
    "malware_ioc":       {"tactic": "Execution",            "technique": "T1204"},
    "phishing":          {"tactic": "Initial Access",       "technique": "T1566"},
    "lateral_movement":  {"tactic": "Lateral Movement",     "technique": "T1021"},
    "data_exfil":        {"tactic": "Exfiltration",         "technique": "T1041"},
    "c2_beacon":         {"tactic": "Command and Control",  "technique": "T1071"},
}

# ── RBAC Roles ────────────────────────────────────────────────────────────────
ROLES = {
    "admin":   ["read", "write", "delete", "simulate", "report"],
    "analyst": ["read", "write", "report"],
    "viewer":  ["read"],
}

# ── Default Users (plain-text for demo; hash in production!) ──────────────────
DEFAULT_USERS = [
    {"username": "admin",   "password": "admin123",   "role": "admin"},
    {"username": "analyst", "password": "analyst123", "role": "analyst"},
    {"username": "viewer",  "password": "viewer123",  "role": "viewer"},
]
