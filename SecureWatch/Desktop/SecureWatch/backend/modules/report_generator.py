"""
SOC Report Generator
=====================
Generates daily and weekly SOC reports in JSON and HTML formats.
Covers: incident counts, attack types, severity breakdown,
response times, top attackers, and analyst activity.
"""

import json
from datetime import datetime, timedelta
from database.db import query, insert

# ── Jinja2 HTML Template ──────────────────────────────────────────────────────

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SOC Report — {report_type} | {period}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  h1 {{ color: #58a6ff; margin-bottom: 0.5rem; }}
  h2 {{ color: #79c0ff; margin: 1.5rem 0 0.5rem; }}
  .meta {{ color: #8b949e; font-size: 0.9rem; margin-bottom: 2rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; }}
  .card .num {{ font-size: 2rem; font-weight: 700; }}
  .card .lbl {{ font-size: 0.8rem; color: #8b949e; margin-top: 0.3rem; }}
  .CRITICAL {{ color: #f85149; }} .HIGH {{ color: #ff7b72; }}
  .MEDIUM {{ color: #e3b341; }} .LOW {{ color: #3fb950; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; }}
  th {{ background: #161b22; color: #58a6ff; padding: 0.6rem 0.8rem; text-align: left; font-size: 0.85rem; }}
  td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid #21262d; font-size: 0.85rem; }}
  tr:hover td {{ background: #161b22; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
  .badge-CRITICAL {{ background: #3d1212; color: #f85149; }}
  .badge-HIGH {{ background: #2d1e18; color: #ff7b72; }}
  .badge-MEDIUM {{ background: #2d2618; color: #e3b341; }}
  .badge-LOW {{ background: #122d1a; color: #3fb950; }}
  footer {{ margin-top: 3rem; color: #484f58; font-size: 0.8rem; text-align: center; }}
</style>
</head>
<body>
<h1>🛡️ Mini SOC Lab — {report_type} Report</h1>
<p class="meta">Period: <strong>{period}</strong>  |  Generated: <strong>{generated_at}</strong>  |  Classification: INTERNAL</p>

<h2>Executive Summary</h2>
<div class="grid">
  <div class="card"><div class="num">{total_alerts}</div><div class="lbl">Total Alerts</div></div>
  <div class="card"><div class="num">{critical_alerts}</div><div class="lbl CRITICAL">Critical</div></div>
  <div class="card"><div class="num">{total_incidents}</div><div class="lbl">Incidents</div></div>
  <div class="card"><div class="num">{open_incidents}</div><div class="lbl">Open</div></div>
  <div class="card"><div class="num">{closed_incidents}</div><div class="lbl">Closed</div></div>
  <div class="card"><div class="num">{ioc_hits}</div><div class="lbl">IOC Hits</div></div>
</div>

<h2>Severity Breakdown</h2>
<table>
<tr><th>Severity</th><th>Alert Count</th><th>% of Total</th></tr>
{severity_rows}
</table>

<h2>Top Attack Types</h2>
<table>
<tr><th>Rule</th><th>Count</th><th>MITRE Tactic</th></tr>
{rule_rows}
</table>

<h2>Top Source IPs</h2>
<table>
<tr><th>IP Address</th><th>Alerts</th><th>Last Seen</th></tr>
{ip_rows}
</table>

<h2>Recent Incidents</h2>
<table>
<tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Assigned To</th><th>Created</th></tr>
{incident_rows}
</table>

<footer>Mini SOC Lab &mdash; Confidential &mdash; For Internal Use Only</footer>
</body>
</html>
"""


# ── Data gathering ────────────────────────────────────────────────────────────

def _get_report_data(since: str) -> dict:
    """Aggregate all metrics for a given time period (ISO timestamp)."""

    # Alerts
    all_alerts = query(
        "SELECT * FROM alerts WHERE created_at >= ?", (since,)
    )
    total_alerts = len(all_alerts)
    sev_counts = {}
    rule_counts = {}
    ip_counts = {}

    for a in all_alerts:
        sv = a.get("severity", "UNKNOWN")
        sev_counts[sv] = sev_counts.get(sv, 0) + 1
        rn = a.get("rule_name", "Unknown")
        rule_counts[rn] = rule_counts.get(rn, 0) + 1
        ip = a.get("source_ip")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    # Incidents
    all_incidents = query(
        "SELECT * FROM incidents WHERE created_at >= ?", (since,)
    )
    open_inc = [i for i in all_incidents if i["status"] != "CLOSED"]
    closed_inc = [i for i in all_incidents if i["status"] == "CLOSED"]

    # IOC hits
    ioc_hits = len(query(
        "SELECT id FROM alerts WHERE rule_id='IOC-001' AND created_at >= ?", (since,)
    ))

    # Top IPs (sorted)
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    # Top rules
    top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Rule → mitre tactic
    rule_tactic_map = {}
    for a in all_alerts:
        rule_tactic_map[a.get("rule_name", "")] = a.get("mitre_tactic", "")

    return {
        "total_alerts":     total_alerts,
        "critical_alerts":  sev_counts.get("CRITICAL", 0),
        "sev_counts":       sev_counts,
        "total_incidents":  len(all_incidents),
        "open_incidents":   len(open_inc),
        "closed_incidents": len(closed_inc),
        "ioc_hits":         ioc_hits,
        "top_ips":          top_ips,
        "top_rules":        top_rules,
        "rule_tactic_map":  rule_tactic_map,
        "incidents":        all_incidents[:10],
    }


# ── HTML rendering ────────────────────────────────────────────────────────────

def _render_html(data: dict, report_type: str, period: str) -> str:
    total = max(data["total_alerts"], 1)

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_rows = ""
    for sv in sev_order:
        cnt = data["sev_counts"].get(sv, 0)
        pct = round(cnt / total * 100, 1)
        severity_rows += (
            f'<tr><td><span class="badge badge-{sv}">{sv}</span></td>'
            f'<td>{cnt}</td><td>{pct}%</td></tr>'
        )

    rule_rows = ""
    for rn, cnt in data["top_rules"]:
        tactic = data["rule_tactic_map"].get(rn, "—")
        rule_rows += f"<tr><td>{rn}</td><td>{cnt}</td><td>{tactic}</td></tr>"

    ip_rows = ""
    for ip, cnt in data["top_ips"]:
        # Get last seen
        rows = query(
            "SELECT MAX(timestamp) as ls FROM alerts WHERE source_ip=?", (ip,)
        )
        ls = rows[0]["ls"] if rows else "—"
        ip_rows += f"<tr><td>{ip}</td><td>{cnt}</td><td>{ls}</td></tr>"

    incident_rows = ""
    for inc in data["incidents"]:
        sv = inc.get("severity", "LOW")
        incident_rows += (
            f'<tr><td>#{inc["id"]}</td>'
            f'<td>{inc["title"]}</td>'
            f'<td><span class="badge badge-{sv}">{sv}</span></td>'
            f'<td>{inc["status"]}</td>'
            f'<td>{inc.get("assigned_to") or "Unassigned"}</td>'
            f'<td>{inc["created_at"]}</td></tr>'
        )

    return REPORT_TEMPLATE.format(
        report_type=report_type,
        period=period,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_alerts=data["total_alerts"],
        critical_alerts=data["critical_alerts"],
        total_incidents=data["total_incidents"],
        open_incidents=data["open_incidents"],
        closed_incidents=data["closed_incidents"],
        ioc_hits=data["ioc_hits"],
        severity_rows=severity_rows,
        rule_rows=rule_rows,
        ip_rows=ip_rows,
        incident_rows=incident_rows,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def generate_daily_report() -> dict:
    """Generate a daily SOC report for the last 24 hours."""
    since = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    period = datetime.now().strftime("%Y-%m-%d")
    data = _get_report_data(since)
    html = _render_html(data, "Daily", period)
    row_id = insert("reports", {
        "report_type": "daily",
        "period":      period,
        "summary":     json.dumps(data, default=str),
        "html":        html,
    })
    return {"id": row_id, "report_type": "daily", "period": period, "summary": data, "html": html}


def generate_weekly_report() -> dict:
    """Generate a weekly SOC report for the last 7 days."""
    since = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    period = (
        f"{(datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')} "
        f"to {datetime.now().strftime('%Y-%m-%d')}"
    )
    data = _get_report_data(since)
    html = _render_html(data, "Weekly", period)
    row_id = insert("reports", {
        "report_type": "weekly",
        "period":      period,
        "summary":     json.dumps(data, default=str),
        "html":        html,
    })
    return {"id": row_id, "report_type": "weekly", "period": period, "summary": data, "html": html}


def get_reports(report_type: str = None) -> list[dict]:
    """Fetch previously generated reports."""
    if report_type:
        return query(
            "SELECT id, report_type, period, created_at FROM reports "
            "WHERE report_type=? ORDER BY id DESC", (report_type,)
        )
    return query(
        "SELECT id, report_type, period, created_at FROM reports ORDER BY id DESC"
    )


def get_report_html(report_id: int) -> str | None:
    """Fetch the HTML content of a specific report."""
    rows = query("SELECT html FROM reports WHERE id=?", (report_id,))
    return rows[0]["html"] if rows else None
