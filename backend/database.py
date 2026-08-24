import sqlite3
import os
from datetime import datetime

DATABASE = os.path.join(os.path.dirname(__file__), "threats.db")


def get_connection():
    """Open a SQLite connection with a busy timeout to avoid lock errors
    when several background threads read/write at the same time."""
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=10000")
    except Exception:
        pass
    return conn


def initialize_database():

    conn = get_connection()

    # WAL mode lets dashboard reads run concurrently with
    # capture/demo writes without 'database is locked' errors.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass

    cursor = conn.cursor()

    # ---------------- Threats Table ----------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        source_port INTEGER,
        destination_port INTEGER,
        protocol TEXT,
        attack_type TEXT,
        confidence REAL
    )
    """)

    # Migration: add new columns if they don't exist yet
    existing = {row[1] for row in cursor.execute("PRAGMA table_info(threats)")}

    if "packet_size" not in existing:
        cursor.execute("ALTER TABLE threats ADD COLUMN packet_size INTEGER DEFAULT 0")

    if "tcp_flags" not in existing:
        cursor.execute("ALTER TABLE threats ADD COLUMN tcp_flags TEXT DEFAULT ''")

    if "severity" not in existing:
        cursor.execute("ALTER TABLE threats ADD COLUMN severity TEXT DEFAULT 'None'")

    if "bytes" not in existing:
        cursor.execute("ALTER TABLE threats ADD COLUMN bytes INTEGER DEFAULT 0")

    if "scanned_ports" not in existing:
        cursor.execute("ALTER TABLE threats ADD COLUMN scanned_ports INTEGER DEFAULT 0")

    # ---------------- Events Table (Live Pipeline Log) ----------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        stage TEXT,
        message TEXT,
        details TEXT
    )
    """)

    # ---------------- Flow Features (stored for retraining) ----------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS flow_features(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id INTEGER,
        features_json TEXT,
        attack_type TEXT
    )
    """)

    conn.commit()
    conn.close()


INSERT_THREAT_SQL = """
INSERT INTO threats(
    timestamp,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol,
    attack_type,
    confidence,
    packet_size,
    tcp_flags,
    severity,
    bytes,
    scanned_ports
)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
"""


def insert_prediction(
        timestamp,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        attack,
        confidence,
        packet_size=0,
        tcp_flags="",
        severity="None",
        bytes_total=0,
        scanned_ports=0
):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(INSERT_THREAT_SQL, (
        timestamp,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        attack,
        confidence,
        packet_size,
        tcp_flags,
        severity,
        bytes_total,
        scanned_ports
    ))

    threat_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return threat_id


def insert_predictions_batch(records):
    """Insert many predictions inside a single transaction.

    `records` is a list of dicts with keys:
      timestamp, src_ip, dst_ip, src_port, dst_port, protocol, attack,
      confidence, packet_size, tcp_flags, severity, bytes_total.
    Returns a list of threat ids in the same order.
    """
    conn = get_connection()
    cursor = conn.cursor()
    ids = []

    for r in records:
        cursor.execute(INSERT_THREAT_SQL, (
            r["timestamp"],
            r["src_ip"],
            r["dst_ip"],
            r["src_port"],
            r["dst_port"],
            r["protocol"],
            r["attack"],
            float(r["confidence"]),
            r.get("packet_size", 0),
            r.get("tcp_flags", ""),
            r.get("severity", "None"),
            r.get("bytes_total", 0),
            r.get("scanned_ports", 0),
        ))
        ids.append(cursor.lastrowid)

    conn.commit()
    conn.close()
    return ids


def insert_flow_features(threat_id, attack, features):
    """Store the 78-feature vector used for this prediction (for retraining)."""
    import json

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO flow_features(threat_id, features_json, attack_type)
    VALUES(?,?,?)
    """, (
        threat_id,
        json.dumps({str(k): float(v) for k, v in features.items()}),
        attack,
    ))
    conn.commit()
    conn.close()


def insert_flow_features_batch(records):
    """Insert many flow-feature rows inside a single transaction.

    `records` is a list of (threat_id, attack_type, features_dict).
    """
    import json

    conn = get_connection()
    cursor = conn.cursor()

    for threat_id, attack, features in records:
        cursor.execute("""
        INSERT INTO flow_features(threat_id, features_json, attack_type)
        VALUES(?,?,?)
        """, (
            threat_id,
            json.dumps({str(k): float(v) for k, v in features.items()}),
            attack,
        ))

    conn.commit()
    conn.close()


def fetch_flow_features(limit=5000):
    import json

    conn = get_connection()
    rows = conn.execute(
        "SELECT attack_type, features_json FROM flow_features ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [
        {"attack_type": r["attack_type"], "features": json.loads(r["features_json"])}
        for r in rows
    ]


def reset_threats():
    """Delete all recorded threats, events, and flow features."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM threats")
    cursor.execute("DELETE FROM events")
    cursor.execute("DELETE FROM flow_features")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('threats','events','flow_features')")
    conn.commit()
    conn.close()


def insert_event(stage, message, details=""):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO events(timestamp, stage, message, details)
    VALUES(?,?,?,?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        stage,
        message,
        details
    ))

    conn.commit()
    conn.close()


def fetch_history(limit=200):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM threats ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def fetch_events(limit=150):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]