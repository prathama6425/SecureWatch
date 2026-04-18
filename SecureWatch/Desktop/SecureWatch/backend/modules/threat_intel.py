"""
Threat Intelligence Module
===========================
Matches log source IPs and domains against bundled IOC feeds.
Generates CRITICAL alerts on IOC hits.
"""

import json
import os
from datetime import datetime
from database.db import query, insert, execute
from config import IOC_IPS_FILE, IOC_DOMAINS_FILE

# ── IOC Cache (in-memory) ─────────────────────────────────────────────────────

_ioc_ips: set = set()
_ioc_domains: set = set()
_ioc_metadata: dict = {}   # value → {category, confidence, source}


def load_ioc_feeds():
    """Load IOC feeds from JSON files into memory."""
    global _ioc_ips, _ioc_domains, _ioc_metadata

    if os.path.exists(IOC_IPS_FILE):
        with open(IOC_IPS_FILE) as f:
            data = json.load(f)
        for entry in data:
            ip = entry["value"]
            _ioc_ips.add(ip)
            _ioc_metadata[ip] = entry

    if os.path.exists(IOC_DOMAINS_FILE):
        with open(IOC_DOMAINS_FILE) as f:
            data = json.load(f)
        for entry in data:
            domain = entry["value"]
            _ioc_domains.add(domain)
            _ioc_metadata[domain] = entry

    # Bulk insert to DB if needed
    try:
        conn = get_conn()
        for ip in _ioc_ips:
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO iocs (type, value, category, confidence, source) VALUES (?,?,?,?,?)",
                    ("ip", ip, _ioc_metadata[ip].get("category", "unknown"), _ioc_metadata[ip].get("confidence", 80), _ioc_metadata[ip].get("source", "feed"))
                )
            except Exception: pass
        for domain in _ioc_domains:
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO iocs (type, value, category, confidence, source) VALUES (?,?,?,?,?)",
                    ("domain", domain, _ioc_metadata[domain].get("category", "unknown"), _ioc_metadata[domain].get("confidence", 80), _ioc_metadata[domain].get("source", "feed"))
                )
            except Exception: pass
        conn.commit()
        conn.close()
    except Exception:
        pass

    print(f"[ThreatIntel] Loaded {len(_ioc_ips)} malicious IPs, "
          f"{len(_ioc_domains)} malicious domains.")


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── IOC Matching ──────────────────────────────────────────────────────────────

def match_logs_against_iocs(logs: list[dict]) -> list[dict]:
    """
    Check each log's source_ip against the IOC IP set.
    Returns a list of CRITICAL alerts for any hits.
    """
    alerts = []
    seen = set()  # Avoid duplicate alerts for same IP in one batch

    for log in logs:
        ip = log.get("source_ip")
        if not ip or ip in seen:
            continue

        if ip in _ioc_ips:
            seen.add(ip)
            meta = _ioc_metadata.get(ip, {})
            data = {
                "timestamp":    _now(),
                "rule_id":      "IOC-001",
                "rule_name":    "Known Malicious IP Detected",
                "severity":     "CRITICAL",
                "source_ip":    ip,
                "username":     log.get("username"),
                "description":  (
                    f"Source IP {ip} matched IOC feed. "
                    f"Category: {meta.get('category', 'unknown')} | "
                    f"Confidence: {meta.get('confidence', 80)}% | "
                    f"Source: {meta.get('source', 'unknown')}. "
                    f"MITRE T1204 — Known Threat Actor."
                ),
                "mitre_tactic": "Execution",
                "mitre_tech":   "T1204",
                "status":       "OPEN",
            }
            data["id"] = insert("alerts", data)
            alerts.append(data)

    return alerts


def check_ip(ip: str) -> dict:
    """Manual lookup of a single IP against IOC database."""
    if ip in _ioc_ips:
        return {"hit": True, "type": "ip", "metadata": _ioc_metadata.get(ip, {})}
    return {"hit": False}


def check_domain(domain: str) -> dict:
    """Manual lookup of a domain against IOC database."""
    for ioc_domain in _ioc_domains:
        if domain.endswith(ioc_domain) or domain == ioc_domain:
            return {"hit": True, "type": "domain", "metadata": _ioc_metadata.get(ioc_domain, {})}
    return {"hit": False}


def get_all_iocs(ioc_type: str = None) -> list[dict]:
    """Retrieve all IOCs from DB, optionally filtered by type."""
    if ioc_type:
        return query("SELECT * FROM iocs WHERE type=? ORDER BY id DESC", (ioc_type,))
    return query("SELECT * FROM iocs ORDER BY id DESC")


def add_ioc(ioc_type: str, value: str, category: str, confidence: int = 80,
            source: str = "manual") -> dict:
    """Manually add a new IOC to the database and in-memory cache."""
    row_id = insert("iocs", {
        "type": ioc_type, "value": value,
        "category": category, "confidence": confidence, "source": source,
    })
    # Update cache
    if ioc_type == "ip":
        _ioc_ips.add(value)
    elif ioc_type == "domain":
        _ioc_domains.add(value)
    _ioc_metadata[value] = {"category": category, "confidence": confidence, "source": source}
    return {"id": row_id, "value": value, "type": ioc_type}
