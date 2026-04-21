import sqlite3
import json
import os
from datetime import datetime
from config import DB_PATH, DEFAULT_USERS

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    source_type TEXT    NOT NULL,
    source_ip   TEXT,
    dest_ip     TEXT,
    username    TEXT,
    action      TEXT,
    status      TEXT,
    message     TEXT,
    raw         TEXT,
    created_at  TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    rule_id      TEXT    NOT NULL,
    rule_name    TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    source_ip    TEXT,
    username     TEXT,
    description  TEXT,
    mitre_tactic TEXT,
    mitre_tech   TEXT,
    status       TEXT    DEFAULT 'OPEN',
    incident_id  INTEGER,
    created_at   TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS incidents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    status       TEXT    DEFAULT 'TRIAGE',
    assigned_to  TEXT,
    alert_ids    TEXT,
    timeline     TEXT    DEFAULT '[]',
    notes        TEXT,
    created_at   TEXT    DEFAULT (datetime('now')),
    updated_at   TEXT    DEFAULT (datetime('now')),
    closed_at    TEXT
);

CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT    NOT NULL,
    value       TEXT    NOT NULL UNIQUE,
    category    TEXT,
    confidence  INTEGER DEFAULT 80,
    source      TEXT    DEFAULT 'internal',
    created_at  TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE,
    password   TEXT    NOT NULL,
    role       TEXT    NOT NULL,
    last_login TEXT,
    created_at TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_type TEXT    NOT NULL,
    period      TEXT    NOT NULL,
    summary     TEXT,
    html        TEXT,
    created_at  TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT,
    action     TEXT,
    detail     TEXT,
    timestamp  TEXT    DEFAULT (datetime('now'))
);
"""

def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)

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

def insert(table: str, data: dict) -> int:
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
    conn = get_conn()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def execute(sql: str, params: tuple = ()):
    conn = get_conn()
    conn.execute(sql, params)
    conn.commit()
    conn.close()

def count(table: str, where: str = "", params: tuple = ()) -> int:
    sql = f"SELECT COUNT(*) FROM {table}"
    if where:
        sql += f" WHERE {where}"
    conn = get_conn()
    result = conn.execute(sql, params).fetchone()[0]
    conn.close()
    return result
