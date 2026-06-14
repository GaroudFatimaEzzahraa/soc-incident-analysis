import sqlite3
import json
from datetime import datetime

DB_PATH = "/home/wazuh/pfe_soc_project/soc_incidents.db"


def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        type TEXT,
        severity TEXT,
        attacker_ip TEXT,
        target_agent TEXT,
        priority INTEGER,
        confidence INTEGER,
        status TEXT,
        created_at TEXT,
        data TEXT
    )
    """)

    conn.commit()
    conn.close()


def save_incident(incident):
    conn = get_conn()
    cur = conn.cursor()

    incident_id = incident.get("id")
    if not incident_id:
        conn.close()
        return

    status = incident.get("status", "OPEN")

    cur.execute("""
    INSERT OR REPLACE INTO incidents
    (id, type, severity, attacker_ip, target_agent, priority, confidence, status, created_at, data)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        incident_id,
        incident.get("type"),
        incident.get("severity"),
        incident.get("ip"),
        incident.get("target_agent"),
        incident.get("priority", 0),
        incident.get("confidence", 0),
        status,
        datetime.utcnow().isoformat(),
        json.dumps(incident)
    ))

    conn.commit()
    conn.close()


def get_all_incidents():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT data FROM incidents
    ORDER BY created_at DESC
    """)

    rows = cur.fetchall()
    conn.close()

    return [json.loads(row[0]) for row in rows]


def get_incident_by_id(incident_id):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT data FROM incidents WHERE id = ?", (incident_id,))
    row = cur.fetchone()

    conn.close()

    if not row:
        return None

    return json.loads(row[0])


def update_status(incident_id, new_status):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT data FROM incidents WHERE id = ?", (incident_id,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return None

    incident = json.loads(row[0])
    incident["status"] = new_status

    cur.execute("""
    UPDATE incidents
    SET status = ?, data = ?
    WHERE id = ?
    """, (
        new_status,
        json.dumps(incident),
        incident_id
    ))

    conn.commit()
    conn.close()

    return incident


def close_incident(incident_id):
    return update_status(incident_id, "CLOSED")


def reopen_incident(incident_id):
    return update_status(incident_id, "OPEN")
