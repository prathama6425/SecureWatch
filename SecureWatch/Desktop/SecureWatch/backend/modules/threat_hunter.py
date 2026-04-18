"""
Threat Hunting Module
======================
Provides a query-based interface for proactive threat hunting.
Analysts can run predefined queries or write custom SQL-style filters
against the normalized log and alert database.
"""

from database.db import query
from datetime import datetime, timedelta


# ── Predefined Hunting Queries ────────────────────────────────────────────────

PREDEFINED_QUERIES = {
    "hunt_brute_force": {
        "id":          "hunt_brute_force",
        "name":        "Failed Login Storm",
        "description": "Find IPs with 5+ failed login attempts (any source).",
        "category":    "Credential Access — T1110",
        "sql": """
            SELECT source_ip, COUNT(*) as attempts,
                   GROUP_CONCAT(DISTINCT username) as targets,
                   MAX(timestamp) as last_seen
            FROM logs
            WHERE status = 'FAILURE' AND source_ip IS NOT NULL
            GROUP BY source_ip
            HAVING attempts >= 5
            ORDER BY attempts DESC
        """,
    },
    "hunt_port_scan": {
        "id":          "hunt_port_scan",
        "name":        "Port Scan Candidates",
        "description": "Find IPs present in firewall logs with BLOCK actions.",
        "category":    "Discovery — T1046",
        "sql": """
            SELECT source_ip, COUNT(*) as blocked_conns,
                   MAX(timestamp) as last_seen
            FROM logs
            WHERE source_type = 'firewall' AND action = 'BLOCK'
                  AND source_ip IS NOT NULL
            GROUP BY source_ip
            HAVING blocked_conns >= 5
            ORDER BY blocked_conns DESC
        """,
    },
    "hunt_off_hours": {
        "id":          "hunt_off_hours",
        "name":        "Off-Hours Activity",
        "description": "Find successful logins between 22:00 and 06:00.",
        "category":    "Initial Access — T1078",
        "sql": """
            SELECT source_ip, username, timestamp, action
            FROM logs
            WHERE status = 'SUCCESS'
              AND (
                CAST(SUBSTR(timestamp, 12, 2) AS INTEGER) >= 22
                OR CAST(SUBSTR(timestamp, 12, 2) AS INTEGER) < 6
              )
            ORDER BY timestamp DESC
            LIMIT 50
        """,
    },
    "hunt_web_recon": {
        "id":          "hunt_web_recon",
        "name":        "Web Reconnaissance",
        "description": "HTTP requests to sensitive paths (/admin, /.env, etc.).",
        "category":    "Discovery / Initial Access",
        "sql": """
            SELECT source_ip, action, status, timestamp
            FROM logs
            WHERE source_type = 'web'
              AND (
                action LIKE '%/admin%'
                OR action LIKE '%/.env%'
                OR action LIKE '%wp-admin%'
                OR action LIKE '%phpmyadmin%'
                OR action LIKE '%passwd%'
              )
            ORDER BY timestamp DESC
            LIMIT 100
        """,
    },
    "hunt_multi_source_ip": {
        "id":          "hunt_multi_source_ip",
        "name":        "Multi-Source IPs",
        "description": "IPs appearing in more than one log source type.",
        "category":    "Multi-Vector Attack Indicator",
        "sql": """
            SELECT source_ip,
                   COUNT(DISTINCT source_type) as source_count,
                   GROUP_CONCAT(DISTINCT source_type) as sources,
                   COUNT(*) as total_events
            FROM logs
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip
            HAVING source_count >= 2
            ORDER BY total_events DESC
        """,
    },
    "hunt_critical_alerts": {
        "id":          "hunt_critical_alerts",
        "name":        "Open Critical Alerts",
        "description": "All unacknowledged CRITICAL severity alerts.",
        "category":    "Alert Prioritization",
        "sql": """
            SELECT id, timestamp, rule_name, source_ip, username,
                   description, mitre_tactic, mitre_tech
            FROM alerts
            WHERE severity = 'CRITICAL' AND status = 'OPEN'
            ORDER BY timestamp DESC
        """,
    },
    "hunt_top_attackers": {
        "id":          "hunt_top_attackers",
        "name":        "Top Attacking IPs",
        "description": "Source IPs ranked by total alert count.",
        "category":    "Threat Quantification",
        "sql": """
            SELECT source_ip, COUNT(*) as alert_count,
                   GROUP_CONCAT(DISTINCT severity) as severities,
                   MAX(timestamp) as last_alert
            FROM alerts
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY alert_count DESC
            LIMIT 20
        """,
    },
    "hunt_ioc_matches": {
        "id":          "hunt_ioc_matches",
        "name":        "IOC-Matched Logs",
        "description": "All log entries from known-malicious IPs.",
        "category":    "Threat Intelligence — T1204",
        "sql": """
            SELECT l.source_ip, l.timestamp, l.source_type,
                   l.action, l.status, i.category, i.confidence
            FROM logs l
            JOIN iocs i ON l.source_ip = i.value AND i.type = 'ip'
            ORDER BY l.timestamp DESC
            LIMIT 100
        """,
    },
}


# ── Hunt Runners ──────────────────────────────────────────────────────────────

def run_predefined_hunt(query_id: str) -> dict:
    """Execute a predefined hunt query and return results."""
    hunt = PREDEFINED_QUERIES.get(query_id)
    if not hunt:
        raise ValueError(f"Unknown hunt query: '{query_id}'")
    try:
        results = query(hunt["sql"].strip())
    except Exception as e:
        results = []
        print(f"[Hunter] Query error for '{query_id}': {e}")
    return {
        "query_id":    hunt["id"],
        "name":        hunt["name"],
        "description": hunt["description"],
        "category":    hunt["category"],
        "result_count": len(results),
        "results":     results,
        "executed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def run_custom_hunt(custom_sql: str) -> dict:
    """
    Execute a custom (analyst-supplied) SQL query against the DB.
    Safety: Only SELECT statements are allowed.
    """
    sql_clean = custom_sql.strip().upper()
    if not sql_clean.startswith("SELECT"):
        raise ValueError("Only SELECT queries are permitted for custom hunts.")
    # Block destructive keywords
    forbidden = ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "CREATE"]
    for kw in forbidden:
        if kw in sql_clean:
            raise ValueError(f"Forbidden keyword '{kw}' in custom query.")
    try:
        results = query(custom_sql.strip())
    except Exception as e:
        raise ValueError(f"Query execution error: {e}")
    return {
        "query_id":    "custom",
        "name":        "Custom Hunt",
        "description": custom_sql[:100],
        "result_count": len(results),
        "results":     results,
        "executed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def list_predefined_queries() -> list[dict]:
    """Return metadata for all predefined hunt queries."""
    return [
        {
            "id":          q["id"],
            "name":        q["name"],
            "description": q["description"],
            "category":    q["category"],
        }
        for q in PREDEFINED_QUERIES.values()
    ]
