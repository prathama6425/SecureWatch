"""
Database Layer — SQLite ORM
============================
Creates and manages all tables: logs, alerts, incidents,
iocs, users, reports, and audit trail.
"""

import sqlite3
import json
import os
from datetime import datetime
from config import DB_PATH, DEFAULT_USERS

# ── Connection helper ─────────────────────────────────────────────────────────

def get_conn():
    """Return a thread-safe SQLite connection with row_factory."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row          # dict-like rows
    conn.execute("PRAGMA journal_mode=WAL") # better concurrency
    return conn


# ── Schema Init ───────────────────────────────────────────────────────────────

SCHEMA = """
-- Normalized log entries from all sources
CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    source_type TEXT    NOT NULL,   -- linux | web | firewall
    source_ip   TEXT,
    dest_ip     TEXT,
    username    TEXT,
    action      TEXT,
    status      TEXT,
    message     TEXT,
    raw         TEXT,               -- original raw log line
    created_at  TEXT    DEFAULT (datetime('now'))
);

-- Generated security alerts
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    rule_id      TEXT    NOT NULL,
    rule_name    TEXT    NOT NULL,
    severity     TEXT    NOT NULL,  -- LOW|MEDIUM|HIGH|CRITICAL
    source_ip    TEXT,
    username     TEXT,
    description  TEXT,
    mitre_tactic TEXT,
    mitre_tech   TEXT,
    status       TEXT    DEFAULT 'OPEN',  -- OPEN|ACK|CLOSED
    incident_id  INTEGER,
    created_at   TEXT    DEFAULT (datetime('now'))
);

-- Incident / Case management
CREATE TABLE IF NOT EXISTS incidents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    status       TEXT    DEFAULT 'TRIAGE',
    assigned_to  TEXT,
    alert_ids    TEXT,              -- JSON array of alert IDs
    timeline     TEXT    DEFAULT '[]',  -- JSON array of events
    notes        TEXT,
    created_at   TEXT    DEFAULT (datetime('now')),
    updated_at   TEXT    DEFAULT (datetime('now')),
    closed_at    TEXT
);

-- Indicators of Compromise
CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT    NOT NULL,   -- ip | domain | hash
    value       TEXT    NOT NULL UNIQUE,
    category    TEXT,               -- malware | c2 | phishing
    confidence  INTEGER DEFAULT 80,
    source      TEXT    DEFAULT 'internal',
    created_at  TEXT    DEFAULT (datetime('now'))
);

-- Users (RBAC)
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE,
    password   TEXT    NOT NULL,
    role       TEXT    NOT NULL,    -- admin|analyst|viewer
    last_login TEXT,
    created_at TEXT    DEFAULT (datetime('now'))
);

-- Generated reports
CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_type TEXT    NOT NULL,   -- daily | weekly
    period      TEXT    NOT NULL,
    summary     TEXT,               -- JSON summary blob
    html        TEXT,               -- rendered HTML
    created_at  TEXT    DEFAULT (datetime('now'))
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT,
    action     TEXT,
    detail     TEXT,
    timestamp  TEXT    DEFAULT (datetime('now'))
);
"""

def init_db():
    """Create all tables and seed default data."""
    conn = get_conn()
    conn.executescript(SCHEMA)

    # Seed default users
    for u in DEFAULT_USERS:
        try:
            conn.execute(
                "INSERT OR IGNORE INTO users (username, password, role) VALUES (?,?,?)",
                (u["username"], u["password"], u["role"])
            )
        except Exception:
            pass

    conn.commit()
    conn.close()
    print("[DB] Initialized successfully.")


# ── Generic CRUD helpers ──────────────────────────────────────────────────────

def insert(table: str, data: dict) -> int:
    """Insert a row and return the new rowid."""
    conn = get_conn()
    cols = ", ".join(data.keys())
    placeholders = ", ".join(["?"] * len(data))
    cursor = conn.execute(
        f"INSERT INTO {table} ({cols}) VALUES ({placeholders})",
        list(data.values())
    )
    conn.commit()
    rowid = cursor.lastrowid
    conn.close()
    return rowid


def query(sql: str, params: tuple = ()) -> list:
    """Execute a SELECT and return list of dicts."""
    conn = get_conn()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def execute(sql: str, params: tuple = ()):
    """Execute an UPDATE/DELETE statement."""
    conn = get_conn()
    conn.execute(sql, params)
    conn.commit()
    conn.close()


def count(table: str, where: str = "", params: tuple = ()) -> int:
    """Count rows in a table."""
    sql = f"SELECT COUNT(*) FROM {table}"
    if where:
        sql += f" WHERE {where}"
    conn = get_conn()
    result = conn.execute(sql, params).fetchone()[0]
    conn.close()
    return result
