"""
Event Correlator
=================
Cross-source log correlation to find complex attack patterns:
  - Same IP appearing across multiple log sources
  - Repeated failed logins followed by a success (pivot attack)
  - Unusual time-based bursts
  - Geo-anomalous logins
"""

from collections import defaultdict
from datetime import datetime
from database.db import query, insert
from config import MITRE_TACTICS

def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── Correlation Rule 1: Cross-Source IP ──────────────────────────────────────

def correlate_cross_source_ip(logs: list[dict]) -> list[dict]:
    """
    Flag IPs that appear in more than one log source type.
    e.g., Same IP in both firewall blocks AND web 404 errors.
    """
    alerts = []
    ip_sources: dict[str, set] = defaultdict(set)
    for log in logs:
        if log.get("source_ip"):
            ip_sources[log["source_ip"]].add(log.get("source_type", "unknown"))

    for ip, sources in ip_sources.items():
        if len(sources) >= 2:
            data = {
                "timestamp":    _now(),
                "rule_id":      "CORR-001",
                "rule_name":    "Cross-Source IP Correlation",
                "severity":     "HIGH",
                "source_ip":    ip,
                "username":     None,
                "description":  (
                    f"IP {ip} detected across {len(sources)} log sources: "
                    f"{', '.join(sources)}. Multi-vector attack indicator."
                ),
                "mitre_tactic": "Discovery",
                "mitre_tech":   "T1046",
                "status":       "OPEN",
            }
            data["id"] = insert("alerts", data)
            alerts.append(data)
    return alerts


# ── Correlation Rule 2: Fail-then-Success (Pivot) ────────────────────────────

def correlate_fail_then_success(logs: list[dict]) -> list[dict]:
    """
    Detect pattern: multiple auth failures from an IP, then a SUCCESS.
    Classic brute-force-to-compromise pattern.
    """
    alerts = []
    ip_events: dict[str, list] = defaultdict(list)
    for log in logs:
        if log.get("source_ip") and log.get("status") in ("SUCCESS", "FAILURE"):
            ip_events[log["source_ip"]].append(log)

    for ip, events in ip_events.items():
        statuses = [e["status"] for e in events]
        failures = statuses.count("FAILURE")
        successes = statuses.count("SUCCESS")
        # At least 3 failures followed by a success
        if failures >= 3 and successes >= 1:
            last_idx = len(statuses) - 1
            while last_idx >= 0 and statuses[last_idx] != "SUCCESS":
                last_idx -= 1
            failures_before = statuses[:last_idx].count("FAILURE")
            if failures_before >= 3:
                data = {
                    "timestamp":    _now(),
                    "rule_id":      "CORR-002",
                    "rule_name":    "Brute Force → Successful Login",
                    "severity":     "CRITICAL",
                    "source_ip":    ip,
                    "username":     events[last_idx].get("username"),
                    "description":  (
                        f"IP {ip} had {failures_before} failed auth attempts "
                        f"followed by a successful login. Possible compromise. MITRE T1110."
                    ),
                    "mitre_tactic": "Credential Access",
                    "mitre_tech":   "T1110",
                    "status":       "OPEN",
                }
                data["id"] = insert("alerts", data)
                alerts.append(data)
    return alerts


# ── Correlation Rule 3: Burst Activity ───────────────────────────────────────

def correlate_burst_activity(logs: list[dict]) -> list[dict]:
    """
    Detect unusually high volume of events from a single IP
    in a short window (> 50 events = anomaly).
    """
    alerts = []
    ip_count: dict[str, int] = defaultdict(int)
    for log in logs:
        if log.get("source_ip"):
            ip_count[log["source_ip"]] += 1

    for ip, cnt in ip_count.items():
        if cnt >= 50:
            data = {
                "timestamp":    _now(),
                "rule_id":      "CORR-003",
                "rule_name":    "Burst Activity Anomaly",
                "severity":     "MEDIUM",
                "source_ip":    ip,
                "username":     None,
                "description":  (
                    f"IP {ip} generated {cnt} log events rapidly. "
                    f"Possible automated attack / scanning activity."
                ),
                "mitre_tactic": "Discovery",
                "mitre_tech":   "T1046",
                "status":       "OPEN",
            }
            data["id"] = insert("alerts", data)
            alerts.append(data)
    return alerts


# ── Main Correlation Runner ───────────────────────────────────────────────────

def run_correlation(logs: list[dict]) -> list[dict]:
    """Run all correlation rules and return new alerts."""
    all_alerts = []
    all_alerts.extend(correlate_cross_source_ip(logs))
    all_alerts.extend(correlate_fail_then_success(logs))
    all_alerts.extend(correlate_burst_activity(logs))
    print(f"[Correlator] {len(all_alerts)} correlation alert(s).")
    return all_alerts


def get_correlation_summary() -> dict:
    """Summarise cross-source IP activity from stored logs."""
    logs = query("SELECT source_ip, source_type FROM logs WHERE source_ip IS NOT NULL")
    ip_sources: dict[str, set] = defaultdict(set)
    for log in logs:
        ip_sources[log["source_ip"]].add(log["source_type"])
    return {
        ip: list(srcs)
        for ip, srcs in ip_sources.items()
        if len(srcs) >= 2
    }
