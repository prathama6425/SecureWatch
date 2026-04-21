

import json
from datetime import datetime
from database.db import query, insert, execute


VALID_STATUSES = ["TRIAGE", "INVESTIGATE", "RESPOND", "CLOSED"]


ESCALATION_THRESHOLD = 2

def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")



def create_incident(title: str, severity: str, alert_ids: list[int],
                    assigned_to: str = None) -> dict:
    """
    Create a new incident from a list of related alert IDs.
    Automatically sets status to TRIAGE.
    """
    timeline = json.dumps([{
        "timestamp": _now(),
        "action": "incident_created",
        "detail": f"Incident created with {len(alert_ids)} alert(s).",
        "by": assigned_to or "system",
    }])
    data = {
        "title":       title,
        "severity":    severity,
        "status":      "TRIAGE",
        "assigned_to": assigned_to,
        "alert_ids":   json.dumps(alert_ids),
        "timeline":    timeline,
        "notes":       "",
    }
    incident_id = insert("incidents", data)

    # Link alerts to this incident
    for aid in alert_ids:
        execute("UPDATE alerts SET incident_id=? WHERE id=?", (incident_id, aid))

    data["id"] = incident_id
    data["alert_ids"] = alert_ids
    data["timeline"] = json.loads(timeline)
    return data


def get_incident(incident_id: int) -> dict | None:
    """Fetch a single incident by ID, with parsed JSON fields."""
    rows = query("SELECT * FROM incidents WHERE id=?", (incident_id,))
    if not rows:
        return None
    return _parse_incident(rows[0])


def get_all_incidents(status: str = None) -> list[dict]:
    """Fetch all incidents, optionally filtered by status."""
    if status:
        rows = query("SELECT * FROM incidents WHERE status=? ORDER BY id DESC", (status,))
    else:
        rows = query("SELECT * FROM incidents ORDER BY id DESC")
    return [_parse_incident(r) for r in rows]


def _parse_incident(row: dict) -> dict:
    """Deserialize JSON fields in an incident row."""
    try:
        row["alert_ids"] = json.loads(row.get("alert_ids") or "[]")
    except Exception:
        row["alert_ids"] = []
    try:
        row["timeline"] = json.loads(row.get("timeline") or "[]")
    except Exception:
        row["timeline"] = []
    return row


# ── Incident Lifecycle ────────────────────────────────────────────────────────

def transition_incident(incident_id: int, new_status: str,
                         analyst: str, note: str = "") -> dict:
    """
    Move an incident to the next status in the workflow.
    Appends a timeline event.
    """
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{new_status}'. Must be one of {VALID_STATUSES}")

    incident = get_incident(incident_id)
    if not incident:
        raise ValueError(f"Incident {incident_id} not found.")

    timeline = incident.get("timeline", [])
    timeline.append({
        "timestamp": _now(),
        "action":    f"status_changed_to_{new_status.lower()}",
        "detail":    note or f"Status updated to {new_status}.",
        "by":        analyst,
    })

    closed_at = _now() if new_status == "CLOSED" else incident.get("closed_at")

    execute(
        "UPDATE incidents SET status=?, timeline=?, updated_at=?, closed_at=? WHERE id=?",
        (new_status, json.dumps(timeline), _now(), closed_at, incident_id)
    )

    if new_status == "CLOSED":
        # Also close all linked alerts
        for aid in incident.get("alert_ids", []):
            execute("UPDATE alerts SET status='CLOSED' WHERE id=?", (aid,))

    return get_incident(incident_id)


def add_note(incident_id: int, analyst: str, note: str) -> dict:
    """Append an analyst note to an incident's timeline."""
    incident = get_incident(incident_id)
    if not incident:
        raise ValueError(f"Incident {incident_id} not found.")

    timeline = incident.get("timeline", [])
    timeline.append({
        "timestamp": _now(),
        "action":    "analyst_note",
        "detail":    note,
        "by":        analyst,
    })

    # Append to notes field too
    existing_notes = incident.get("notes", "") or ""
    new_notes = f"{existing_notes}\n[{_now()}] {analyst}: {note}".strip()

    execute(
        "UPDATE incidents SET timeline=?, notes=?, updated_at=? WHERE id=?",
        (json.dumps(timeline), new_notes, _now(), incident_id)
    )
    return get_incident(incident_id)


def assign_incident(incident_id: int, analyst: str, assigned_by: str) -> dict:
    """Assign an incident to a specific analyst."""
    incident = get_incident(incident_id)
    if not incident:
        raise ValueError(f"Incident {incident_id} not found.")

    timeline = incident.get("timeline", [])
    timeline.append({
        "timestamp": _now(),
        "action":    "assigned",
        "detail":    f"Incident assigned to '{analyst}'.",
        "by":        assigned_by,
    })

    execute(
        "UPDATE incidents SET assigned_to=?, timeline=?, updated_at=? WHERE id=?",
        (analyst, json.dumps(timeline), _now(), incident_id)
    )
    return get_incident(incident_id)


# ── Auto-Escalation ───────────────────────────────────────────────────────────

def check_escalation() -> list[dict]:
    """
    Auto-escalate TRIAGE incidents that have CRITICAL alerts
    and have not been assigned within a reasonable time.
    Returns list of escalated incident summaries.
    """
    escalated = []
    incidents = get_all_incidents(status="TRIAGE")
    for inc in incidents:
        if inc.get("severity") == "CRITICAL" and not inc.get("assigned_to"):
            try:
                transition_incident(
                    incident_id=inc["id"],
                    new_status="INVESTIGATE",
                    analyst="system-escalator",
                    note="Auto-escalated: CRITICAL severity, unassigned.",
                )
                escalated.append(inc)
            except Exception:
                pass
    return escalated


# ── Stats ─────────────────────────────────────────────────────────────────────

def get_incident_stats() -> dict:
    """Return counts by status and severity."""
    rows = query("""
        SELECT status, severity, COUNT(*) as cnt
        FROM incidents GROUP BY status, severity
    """)
    stats = {"by_status": {}, "by_severity": {}}
    for r in rows:
        st = r["status"]
        sv = r["severity"]
        stats["by_status"][st] = stats["by_status"].get(st, 0) + r["cnt"]
        stats["by_severity"][sv] = stats["by_severity"].get(sv, 0) + r["cnt"]
    return stats
