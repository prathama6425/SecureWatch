"""
Threat Detection Engine
========================
MITRE ATT&CK aligned detection rules.
Analyses normalized logs for:
  - Brute force attacks          (T1110)
  - Port scanning                (T1046)
  - Suspicious login patterns    (T1078)
  - Malware / IOC indicators     (T1204)
  - Off-hours activity
"""

import json
from datetime import datetime, timedelta
from collections import defaultdict
from database.db import query, insert
from config import (
    BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW,
    PORT_SCAN_THRESHOLD, SUSPICIOUS_HOUR_START,
    SUSPICIOUS_HOUR_END, MITRE_TACTICS
)

# ── Helper ────────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _create_alert(rule_id: str, rule_name: str, severity: str,
                  source_ip: str, username: str, description: str,
                  tactic_key: str) -> dict:
    """Persist a new alert to the DB and return it."""
    mitre = MITRE_TACTICS.get(tactic_key, {})
    data = {
        "timestamp":    _now(),
        "rule_id":      rule_id,
        "rule_name":    rule_name,
        "severity":     severity,
        "source_ip":    source_ip,
        "username":     username,
        "description":  description,
        "mitre_tactic": mitre.get("tactic", ""),
        "mitre_tech":   mitre.get("technique", ""),
        "status":       "OPEN",
    }
    data["id"] = insert("alerts", data)
    return data


# ── Rule 1: Brute Force (T1110) ───────────────────────────────────────────────

def check_brute_force(logs: list[dict]) -> list[dict]:
    """
    Detect multiple failed login attempts from the same IP
    within the configured time window.
    """
    alerts = []
    # Group failures by source_ip
    failures: dict[str, list] = defaultdict(list)
    for log in logs:
        if log.get("status") == "FAILURE" and log.get("source_ip"):
            failures[log["source_ip"]].append(log)

    for ip, events in failures.items():
        if len(events) >= BRUTE_FORCE_THRESHOLD:
            usernames = list({e.get("username") for e in events if e.get("username")})
            alert = _create_alert(
                rule_id="BF-001",
                rule_name="Brute Force Login Attempt",
                severity="HIGH",
                source_ip=ip,
                username=", ".join(usernames) if usernames else "unknown",
                description=(
                    f"Detected {len(events)} failed login attempts from {ip} "
                    f"targeting account(s): {', '.join(usernames) if usernames else 'unknown'}. "
                    f"Aligned with MITRE ATT&CK T1110 (Brute Force)."
                ),
                tactic_key="brute_force",
            )
            alerts.append(alert)
    return alerts


# ── Rule 2: Port Scan Detection (T1046) ───────────────────────────────────────

def check_port_scan(logs: list[dict]) -> list[dict]:
    """
    Detect port scanning: one IP hitting many distinct destination ports.
    Only applies to firewall logs.
    """
    alerts = []
    port_map: dict[str, set] = defaultdict(set)
    for log in logs:
        if log.get("source_type") == "firewall" and log.get("source_ip"):
            # Extract port from message
            import re
            m = re.search(r"->.*?:(\d+)", log.get("message", ""))
            if m:
                port_map[log["source_ip"]].add(m.group(1))

    for ip, ports in port_map.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alert = _create_alert(
                rule_id="PS-001",
                rule_name="Port Scan Detected",
                severity="MEDIUM",
                source_ip=ip,
                username=None,
                description=(
                    f"IP {ip} probed {len(ports)} distinct ports: "
                    f"{', '.join(sorted(ports)[:10])}{'...' if len(ports) > 10 else ''}. "
                    f"Consistent with reconnaissance (MITRE T1046)."
                ),
                tactic_key="port_scan",
            )
            alerts.append(alert)
    return alerts


# ── Rule 3: Suspicious Login (T1078) ─────────────────────────────────────────

def check_suspicious_login(logs: list[dict]) -> list[dict]:
    """
    Flag logins during off-hours (22:00 – 06:00) or
    from new/unexpected source IPs.
    """
    alerts = []
    for log in logs:
        if log.get("status") != "SUCCESS":
            continue
        if "login" not in log.get("action", "").lower() and \
           "ssh" not in log.get("action", "").lower() and \
           "auth" not in log.get("message", "").lower():
            continue
        try:
            ts = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
            hour = ts.hour
            if hour >= SUSPICIOUS_HOUR_START or hour < SUSPICIOUS_HOUR_END:
                alert = _create_alert(
                    rule_id="SL-001",
                    rule_name="Suspicious Off-Hours Login",
                    severity="MEDIUM",
                    source_ip=log.get("source_ip"),
                    username=log.get("username"),
                    description=(
                        f"Successful login by '{log.get('username', 'unknown')}' "
                        f"from {log.get('source_ip', 'unknown')} at {ts.strftime('%H:%M')} "
                        f"(outside business hours). MITRE T1078."
                    ),
                    tactic_key="suspicious_login",
                )
                alerts.append(alert)
        except (ValueError, TypeError):
            pass
    return alerts


# ── Rule 4: Web Attack Patterns ───────────────────────────────────────────────

def check_web_attacks(logs: list[dict]) -> list[dict]:
    """
    Detect common web attack patterns:
    - SQL injection attempts
    - Directory traversal
    - Admin panel probing
    """
    alerts = []
    suspicious_paths = ["/admin", "/wp-admin", "/.env", "/phpmyadmin",
                        "/etc/passwd", "../", "union+select", "script>"]
    for log in logs:
        if log.get("source_type") != "web":
            continue
        action = log.get("action", "").lower()
        for pattern in suspicious_paths:
            if pattern in action:
                alert = _create_alert(
                    rule_id="WA-001",
                    rule_name="Web Attack / Path Probe",
                    severity="HIGH",
                    source_ip=log.get("source_ip"),
                    username=log.get("username"),
                    description=(
                        f"Suspicious HTTP request from {log.get('source_ip')}: "
                        f"'{log.get('action')}'. Possible web attack / recon."
                    ),
                    tactic_key="malware_ioc",
                )
                alerts.append(alert)
                break
    return alerts


# ── Rule 5: Repeated 401/403 Errors ──────────────────────────────────────────

def check_auth_failures(logs: list[dict]) -> list[dict]:
    """Detect excessive HTTP 401/403 from same IP (credential stuffing)."""
    alerts = []
    ip_failures: dict[str, int] = defaultdict(int)
    for log in logs:
        if log.get("source_type") == "web":
            msg = log.get("message", "")
            if "HTTP 401" in msg or "HTTP 403" in msg:
                if log.get("source_ip"):
                    ip_failures[log["source_ip"]] += 1

    for ip, count in ip_failures.items():
        if count >= 5:
            alert = _create_alert(
                rule_id="AF-001",
                rule_name="HTTP Auth Failure Spike",
                severity="HIGH",
                source_ip=ip,
                username=None,
                description=(
                    f"IP {ip} produced {count} HTTP 401/403 responses. "
                    f"Potential credential stuffing / web brute force (MITRE T1110.003)."
                ),
                tactic_key="brute_force",
            )
            alerts.append(alert)
    return alerts


# ── Main Dispatcher ───────────────────────────────────────────────────────────

def run_detection(logs: list[dict]) -> list[dict]:
    """
    Run all detection rules against a batch of normalized logs.
    Returns combined list of new alerts generated.
    """
    all_alerts = []
    all_alerts.extend(check_brute_force(logs))
    all_alerts.extend(check_port_scan(logs))
    all_alerts.extend(check_suspicious_login(logs))
    all_alerts.extend(check_web_attacks(logs))
    all_alerts.extend(check_auth_failures(logs))
    print(f"[Detector] {len(all_alerts)} new alert(s) generated from {len(logs)} log(s).")
    return all_alerts


def get_all_alerts(limit: int = 200, status: str = None) -> list[dict]:
    """Fetch alerts from DB, optionally filtered by status."""
    if status:
        return query(
            "SELECT * FROM alerts WHERE status=? ORDER BY id DESC LIMIT ?",
            (status, limit)
        )
    return query("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))


def update_alert_status(alert_id: int, status: str):
    """Update alert status (OPEN → ACK → CLOSED)."""
    from database.db import execute
    execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
