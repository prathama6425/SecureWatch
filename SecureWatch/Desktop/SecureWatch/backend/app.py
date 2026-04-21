
import sys
import os

# Allow sibling imports (modules/, database/)
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import json
from datetime import datetime


app = Flask(__name__, static_folder="../frontend")
app.config["SECRET_KEY"] = "soc-lab-secret-2026"
CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


from database.db import init_db, query, execute, count
from modules.log_collector    import ingest_log_batch, get_recent_logs, get_logs_by_ip
from modules.threat_detector  import run_detection, get_all_alerts, update_alert_status
from modules.correlator        import run_correlation, get_correlation_summary
from modules.threat_intel      import (
    load_ioc_feeds, match_logs_against_iocs,
    get_all_iocs, add_ioc, check_ip, check_domain
)
from modules.incident_response import (
    create_incident, get_all_incidents, get_incident,
    transition_incident, add_note, assign_incident,
    check_escalation, get_incident_stats
)
from modules.threat_hunter    import run_predefined_hunt, run_custom_hunt, list_predefined_queries
from modules.report_generator import generate_daily_report, generate_weekly_report, get_reports, get_report_html
from modules.attack_simulator  import run_simulation


def ok(data=None, msg="ok", **kwargs):
    resp = {"status": "ok", "message": msg}
    if data is not None:
        resp["data"] = data
    resp.update(kwargs)
    return jsonify(resp)


def err(msg, code=400):
    return jsonify({"status": "error", "message": msg}), code


def _get_user(req) -> dict | None:
    """Extract user from a simple token header (demo implementation)."""
    token = req.headers.get("X-Auth-Token", "")
    # Token format: "username:role" 
    if ":" in token:
        parts = token.split(":", 1)
        return {"username": parts[0], "role": parts[1]}
    return None


def _require_role(req, required_roles: list[str]):
    """Return (user, error_response) — error_response is None if OK."""
    user = _get_user(req)
    if not user:
        return None, err("Authentication required. Add X-Auth-Token header.", 401)
    if user["role"] not in required_roles:
        return None, err(f"Role '{user['role']}' lacks permission.", 403)
    return user, None



def _broadcast_alerts(alerts: list[dict]):
    """Push new alerts to all connected WebSocket clients."""
    if alerts:
        socketio.emit("new_alerts", {"alerts": alerts, "count": len(alerts)})


@app.route("/api/auth/login", methods=["POST"])
def login():
    """Authenticate user and return a token."""
    body = request.get_json(force=True) or {}
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()
    rows = query("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    if not rows:
        return err("Invalid credentials.", 401)
    user = rows[0]
    # Simple token: username:role
    token = f"{user['username']}:{user['role']}"
    execute("UPDATE users SET last_login=? WHERE id=?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
    return ok({"token": token, "username": user["username"], "role": user["role"]},
              msg="Login successful.")


@app.route("/api/auth/me", methods=["GET"])
def me():
    user, error = _require_role(request, ["admin", "analyst", "viewer"])
    if error:
        return error
    return ok(user)


@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    """Aggregate metrics for the main dashboard."""
    total_logs    = count("logs")
    total_alerts  = count("alerts")
    open_alerts   = count("alerts", "status='OPEN'")
    critical      = count("alerts", "severity='CRITICAL'")
    high          = count("alerts", "severity='HIGH'")
    medium        = count("alerts", "severity='MEDIUM'")
    low           = count("alerts", "severity='LOW'")
    total_inc     = count("incidents")
    open_inc      = count("incidents", "status != 'CLOSED'")
    total_iocs    = count("iocs")

    # Alert trend
    trend = query("""
        SELECT DATE(created_at) as day, COUNT(*) as cnt
        FROM alerts
        GROUP BY day ORDER BY day DESC LIMIT 7
    """)

   
    sev = query("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")

    # Top attacking IPs
    top_ips = query("""
        SELECT source_ip, COUNT(*) as cnt
        FROM alerts WHERE source_ip IS NOT NULL
        GROUP BY source_ip ORDER BY cnt DESC LIMIT 8
    """)

    # MITRE tactics breakdown
    tactics = query("""
        SELECT mitre_tactic, COUNT(*) as cnt
        FROM alerts WHERE mitre_tactic != ''
        GROUP BY mitre_tactic ORDER BY cnt DESC LIMIT 8
    """)

    
    recent_alerts = get_all_alerts(limit=10)

   
    recent_incidents = get_all_incidents()[:5]

    return ok({
        "totals": {
            "logs": total_logs, "alerts": total_alerts,
            "open_alerts": open_alerts, "incidents": total_inc,
            "open_incidents": open_inc, "iocs": total_iocs,
        },
        "severity": {"critical": critical, "high": high, "medium": medium, "low": low},
        "alert_trend": list(reversed(trend)),
        "severity_breakdown": sev,
        "top_ips": top_ips,
        "mitre_tactics": tactics,
        "recent_alerts": recent_alerts,
        "recent_incidents": recent_incidents,
    })




@app.route("/api/logs", methods=["GET"])
def get_logs():
    source_type = request.args.get("type")
    limit = int(request.args.get("limit", 100))
    logs = get_recent_logs(limit=limit, source_type=source_type)
    return ok(logs, total=len(logs))


@app.route("/api/logs/ingest", methods=["POST"])
def ingest_logs():
    """Ingest raw log lines and run the full detection pipeline."""
    user, error = _require_role(request, ["admin", "analyst"])
    if error:
        return error
    body = request.get_json(force=True) or {}
    lines = body.get("lines", [])
    source_type = body.get("source_type", "linux")

    if not lines:
        return err("'lines' array is required.")
    if source_type not in ("linux", "web", "firewall"):
        return err("source_type must be: linux, web, or firewall")

    logs = ingest_log_batch(lines, source_type)
    alerts = run_detection(logs)
    alerts += run_correlation(logs)
    alerts += match_logs_against_iocs(logs)
    _broadcast_alerts(alerts)

    return ok({
        "logs_ingested": len(logs),
        "alerts_generated": len(alerts),
        "alerts": alerts,
    }, msg=f"Ingested {len(logs)} log(s), generated {len(alerts)} alert(s).")


@app.route("/api/logs/load-samples", methods=["POST"])
def load_sample_logs():
    """Load all bundled sample log files and run the detection pipeline."""
    user, error = _require_role(request, ["admin", "analyst"])
    if error:
        return error

    from config import DATA_DIR
    samples = [
        ("linux",    os.path.join(DATA_DIR, "sample_logs", "linux.log")),
        ("web",      os.path.join(DATA_DIR, "sample_logs", "web.log")),
        ("firewall", os.path.join(DATA_DIR, "sample_logs", "firewall.log")),
    ]

    total_logs, total_alerts = 0, 0
    for source_type, path in samples:
        if os.path.exists(path):
            with open(path) as f:
                lines = f.readlines()
            logs = ingest_log_batch(lines, source_type)
            alerts = run_detection(logs)
            alerts += run_correlation(logs)
            alerts += match_logs_against_iocs(logs)
            _broadcast_alerts(alerts)
            total_logs += len(logs)
            total_alerts += len(alerts)

    return ok({
        "logs_ingested": total_logs,
        "alerts_generated": total_alerts,
    }, msg=f"Loaded sample logs: {total_logs} entries, {total_alerts} alerts.")


@app.route("/api/logs/ip/<ip>", methods=["GET"])
def logs_by_ip(ip):
    return ok(get_logs_by_ip(ip))



@app.route("/api/alerts", methods=["GET"])
def alerts():
    status = request.args.get("status")
    limit = int(request.args.get("limit", 200))
    return ok(get_all_alerts(limit=limit, status=status), total=count("alerts"))


@app.route("/api/alerts/<int:alert_id>", methods=["GET"])
def get_alert(alert_id):
    rows = query("SELECT * FROM alerts WHERE id=?", (alert_id,))
    if not rows:
        return err("Alert not found.", 404)
    return ok(rows[0])


@app.route("/api/alerts/<int:alert_id>/status", methods=["PATCH"])
def patch_alert_status(alert_id):
    user, error = _require_role(request, ["admin", "analyst"])
    if error:
        return error
    body = request.get_json(force=True) or {}
    status = body.get("status", "").upper()
    if status not in ("OPEN", "ACK", "CLOSED"):
        return err("status must be OPEN, ACK, or CLOSED")
    update_alert_status(alert_id, status)
    return ok(msg=f"Alert {alert_id} status updated to {status}.")



@app.route("/api/incidents", methods=["GET"])
def incidents():
    status = request.args.get("status")
    return ok(get_all_incidents(status=status), stats=get_incident_stats())


@app.route("/api/incidents/<int:inc_id>", methods=["GET"])
def get_inc(inc_id):
    inc = get_incident(inc_id)
    if not inc:
        return err("Incident not found.", 404)
    return ok(inc)


@app.route("/api/incidents", methods=["POST"])
def create_inc():
    user, error = _require_role(request, ["admin", "analyst"])
    if error:
        return error
    body = request.get_json(force=True) or {}
    title      = body.get("title", "").strip()
    severity   = body.get("severity", "MEDIUM").upper()
    alert_ids  = body.get("alert_ids", [])
    assigned   = body.get("assigned_to", user["username"])
    if not title:
        return err("'title' is required.")
    inc = create_incident(title, severity, alert_ids, assigned)
    _broadcast_alerts([])  # notify clients of new incident
    socketio.emit("new_incident", inc)
    return ok(inc, msg="Incident created.")


@app.route("/api/incidents/<int:inc_id>/transition", methods=["POST"])
def transition_inc(inc_id):
    user, error = _require_role(request, ["admin", "analyst"])
    if error:
        return error
    body = request.get_json(force=True) or {}
    new_status = body.get("status", "").upper()
    note       = body.get("note", "")
    inc = transition_incident(inc_id, new_status, user["username"], note)
    socketio.emit("incident_update", inc)
    return ok(inc, msg=f"Incident transitioned to {new_status}.")


@app.route("/api/incidents/<int:inc_id>/note", methods=["POST"])
def add_inc_note(inc_id):
    user, error = _require_role(request, ["admin", "analyst"])
    if error:
        return error
    body = request.get_json(force=True) or {}
    note = body.get("note", "").strip()
    if not note:
        return err("'note' is required.")
    inc = add_note(inc_id, user["username"], note)
    return ok(inc, msg="Note added.")


@app.route("/api/incidents/<int:inc_id>/assign", methods=["POST"])
def assign_inc(inc_id):
    user, error = _require_role(request, ["admin"])
    if error:
        return error
    body = request.get_json(force=True) or {}
    analyst = body.get("analyst", "").strip()
    inc = assign_incident(inc_id, analyst, user["username"])
    return ok(inc, msg=f"Assigned to {analyst}.")


@app.route("/api/incidents/escalation/check", methods=["POST"])
def escalation_check():
    user, error = _require_role(request, ["admin"])
    if error:
        return error
    escalated = check_escalation()
    return ok(escalated, msg=f"{len(escalated)} incident(s) auto-escalated.")


@app.route("/api/iocs", methods=["GET"])
def iocs():
    ioc_type = request.args.get("type")
    return ok(get_all_iocs(ioc_type), total=count("iocs"))


@app.route("/api/iocs/check", methods=["POST"])
def check_ioc():
    body = request.get_json(force=True) or {}
    ip     = body.get("ip")
    domain = body.get("domain")
    if ip:
        return ok(check_ip(ip))
    if domain:
        return ok(check_domain(domain))
    return err("Provide 'ip' or 'domain'")


@app.route("/api/iocs", methods=["POST"])
def add_ioc_endpoint():
    user, error = _require_role(request, ["admin"])
    if error:
        return error
    body = request.get_json(force=True) or {}
    ioc_type   = body.get("type", "ip")
    value      = body.get("value", "").strip()
    category   = body.get("category", "unknown")
    confidence = int(body.get("confidence", 80))
    source     = body.get("source", "manual")
    if not value:
        return err("'value' is required.")
    result = add_ioc(ioc_type, value, category, confidence, source)
    return ok(result, msg="IOC added.")



@app.route("/api/hunt/queries", methods=["GET"])
def hunt_queries():
    return ok(list_predefined_queries())


@app.route("/api/hunt/run/<query_id>", methods=["GET"])
def hunt_run_predefined(query_id):
    user, error = _require_role(request, ["admin", "analyst"])
    if error:
        return error
    try:
        result = run_predefined_hunt(query_id)
        return ok(result)
    except ValueError as e:
        return err(str(e))


@app.route("/api/hunt/custom", methods=["POST"])
def hunt_custom():
    user, error = _require_role(request, ["admin", "analyst"])
    if error:
        return error
    body = request.get_json(force=True) or {}
    sql = body.get("sql", "").strip()
    if not sql:
        return err("'sql' is required.")
    try:
        result = run_custom_hunt(sql)
        return ok(result)
    except ValueError as e:
        return err(str(e))



@app.route("/api/reports", methods=["GET"])
def reports():
    report_type = request.args.get("type")
    return ok(get_reports(report_type))


@app.route("/api/reports/generate/daily", methods=["POST"])
def gen_daily():
    user, error = _require_role(request, ["admin", "analyst"])
    if error:
        return error
    report = generate_daily_report()
    # Return without the full HTML 
    report_meta = {k: v for k, v in report.items() if k != "html"}
    report_meta["html_url"] = f"/api/reports/{report['id']}/html"
    return ok(report_meta, msg="Daily report generated.")


@app.route("/api/reports/generate/weekly", methods=["POST"])
def gen_weekly():
    user, error = _require_role(request, ["admin", "analyst"])
    if error:
        return error
    report = generate_weekly_report()
    report_meta = {k: v for k, v in report.items() if k != "html"}
    report_meta["html_url"] = f"/api/reports/{report['id']}/html"
    return ok(report_meta, msg="Weekly report generated.")


@app.route("/api/reports/<int:report_id>/html", methods=["GET"])
def report_html(report_id):
    from flask import Response
    html = get_report_html(report_id)
    if not html:
        return err("Report not found.", 404)
    return Response(html, mimetype="text/html")



@app.route("/api/simulate", methods=["POST"])
def simulate():
    user, error = _require_role(request, ["admin"])
    if error:
        return error
    body = request.get_json(force=True) or {}
    sim_type    = body.get("type", "brute_force")
    attacker_ip = body.get("attacker_ip")
    try:
        result = run_simulation(sim_type, attacker_ip)
        _broadcast_alerts(result.get("alerts", []))
        socketio.emit("simulation_complete", {
            "type": sim_type,
            "logs": result.get("logs_ingested") or result.get("total_logs", 0),
            "alerts": result.get("alerts_generated") or result.get("total_alerts", 0),
        })
        return ok(result, msg=f"Simulation '{sim_type}' completed.")
    except ValueError as e:
        return err(str(e))



@app.route("/api/users", methods=["GET"])
def users():
    user, error = _require_role(request, ["admin"])
    if error:
        return error
    rows = query("SELECT id, username, role, last_login, created_at FROM users")
    return ok(rows)



@app.route("/api/correlation", methods=["GET"])
def correlation():
    return ok(get_correlation_summary())



@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
    if path and os.path.exists(os.path.join(frontend_dir, path)):
        return send_from_directory(frontend_dir, path)
    return send_from_directory(frontend_dir, "index.html")


@socketio.on("connect")
def on_connect():
    print(f"[WS] Client connected: {request.sid}")
    emit("connected", {"message": "SOC Lab WebSocket connected."})


@socketio.on("disconnect")
def on_disconnect():
    print(f"[WS] Client disconnected: {request.sid}")



if __name__ == "__main__":
    print("=" * 60)
    print("  Mini SOC Lab — SIEM Threat Detection System")
    print("  Starting server on http://localhost:5000")
    print("=" * 60)

    init_db()

    load_ioc_feeds()

    socketio.run(app, host="0.0.0.0", port=5000, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)
