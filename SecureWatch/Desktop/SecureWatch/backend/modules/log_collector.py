"""
Log Collector & Normalizer
===========================
Parses raw Linux syslog, Apache/Nginx web logs, and
simulated firewall logs into a unified JSON schema,
then persists them to the database.
"""

import re
import json
from datetime import datetime
from database.db import insert, query

# ── Regex patterns for each log type ─────────────────────────────────────────

# Linux syslog: Apr 15 10:22:01 hostname sshd[1234]: Failed password for root from 192.168.1.10
LINUX_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.+)"
)

# Apache Combined Log: 192.168.1.10 - frank [10/Apr/2026:13:55:36 -0700] "GET /admin HTTP/1.1" 401 512
WEB_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
)

# Firewall: 2026-04-15 10:22:01 BLOCK TCP 1.2.3.4:54321 -> 10.0.0.5:22 (rule: ssh-block)
FIREWALL_PATTERN = re.compile(
    r"(?P<date>[\d-]+)\s+(?P<time>[\d:]+)\s+(?P<action>\w+)\s+(?P<proto>\w+)\s+"
    r"(?P<src>[\d.]+):(?P<sport>\d+)\s+->\s+(?P<dst>[\d.]+):(?P<dport>\d+)"
    r"(?:\s+\(rule:\s*(?P<rule>[^)]+)\))?"
)


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_linux_log(line: str) -> dict | None:
    """Parse a Linux syslog line into a normalized dict."""
    m = LINUX_PATTERN.match(line.strip())
    if not m:
        return None
    msg = m.group("message")
    # Extract IP from message if present
    ip_match = re.search(r"from\s+([\d.]+)", msg)
    user_match = re.search(r"for\s+(\S+)\s+from", msg)
    # Determine status
    status = "FAILURE" if any(w in msg.lower() for w in ["failed", "invalid", "error"]) else "SUCCESS"
    return {
        "timestamp":   f"2026-04-15 {m.group('time')}",
        "source_type": "linux",
        "source_ip":   ip_match.group(1) if ip_match else None,
        "dest_ip":     None,
        "username":    user_match.group(1) if user_match else None,
        "action":      m.group("process").split("[")[0],
        "status":      status,
        "message":     msg,
        "raw":         line.strip(),
    }


def parse_web_log(line: str) -> dict | None:
    """Parse an Apache/Nginx combined log line."""
    m = WEB_PATTERN.match(line.strip())
    if not m:
        return None
    status_code = int(m.group("status"))
    status = "FAILURE" if status_code >= 400 else "SUCCESS"
    return {
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_type": "web",
        "source_ip":   m.group("ip"),
        "dest_ip":     None,
        "username":    m.group("user") if m.group("user") != "-" else None,
        "action":      f"{m.group('method')} {m.group('path')}",
        "status":      status,
        "message":     f"HTTP {m.group('status')} {m.group('method')} {m.group('path')}",
        "raw":         line.strip(),
    }


def parse_firewall_log(line: str) -> dict | None:
    """Parse a simulated firewall log line."""
    m = FIREWALL_PATTERN.match(line.strip())
    if not m:
        return None
    return {
        "timestamp":   f"{m.group('date')} {m.group('time')}",
        "source_type": "firewall",
        "source_ip":   m.group("src"),
        "dest_ip":     m.group("dst"),
        "username":    None,
        "action":      m.group("action"),          # ALLOW | BLOCK | DROP
        "status":      m.group("action"),
        "message":     (
            f"{m.group('action')} {m.group('proto')} "
            f"{m.group('src')}:{m.group('sport')} -> "
            f"{m.group('dst')}:{m.group('dport')}"
            + (f" rule:{m.group('rule')}" if m.group("rule") else "")
        ),
        "raw":         line.strip(),
    }


# ── Dispatcher ────────────────────────────────────────────────────────────────

PARSERS = {
    "linux":    parse_linux_log,
    "web":      parse_web_log,
    "firewall": parse_firewall_log,
}


def ingest_log_line(line: str, source_type: str) -> dict | None:
    """
    Parse a single raw log line of the given source_type,
    persist it to the DB, and return the normalized record.
    """
    parser = PARSERS.get(source_type)
    if not parser:
        return None
    record = parser(line)
    if record:
        record["id"] = insert("logs", record)
    return record


def ingest_log_batch(lines: list[str], source_type: str) -> list[dict]:
    """Parse and ingest a batch of raw log lines."""
    results = []
    for line in lines:
        if line.strip():
            r = ingest_log_line(line, source_type)
            if r:
                results.append(r)
    return results


def get_recent_logs(limit: int = 100, source_type: str = None) -> list[dict]:
    """Fetch the most recent normalized logs."""
    if source_type:
        return query(
            "SELECT * FROM logs WHERE source_type=? ORDER BY id DESC LIMIT ?",
            (source_type, limit)
        )
    return query("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,))


def get_logs_by_ip(ip: str) -> list[dict]:
    """Fetch all logs associated with a specific source IP."""
    return query(
        "SELECT * FROM logs WHERE source_ip=? ORDER BY timestamp DESC",
        (ip,)
    )
