# db.py
import sqlite3

DB_NAME = "audit.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    # Ensure scans table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        status TEXT,
        score INTEGER,
        created_at TEXT
    )
    """)

    # Ensure findings table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        page TEXT,
        type TEXT,
        parameter TEXT,
        evidence TEXT,
        severity TEXT,
        owasp_mapping TEXT,
        recommendation TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )
    """)

    # --- AUTO-MIGRATION FIX FOR OLD DATABASES ---
    # Check existing columns in scans table
    cur.execute("PRAGMA table_info(scans)")
    scans_cols = [r[1] for r in cur.fetchall()]

    if "created_at" not in scans_cols:
        print("🔧 Adding missing 'created_at' column to scans table...")
        cur.execute("ALTER TABLE scans ADD COLUMN created_at TEXT")
        cur.execute("UPDATE scans SET created_at = datetime('now')")  # assign timestamps

    # Ensure findings columns exist
    expected_findings = [
        ("page", "TEXT"),
        ("type", "TEXT"),
        ("parameter", "TEXT"),
        ("evidence", "TEXT"),
        ("severity", "TEXT"),
        ("owasp_mapping", "TEXT"),
        ("recommendation", "TEXT"),
    ]

    cur.execute("PRAGMA table_info(findings)")
    findings_cols = [r[1] for r in cur.fetchall()]

    for col, col_type in expected_findings:
        if col not in findings_cols:
            print(f"🔧 Adding missing column '{col}' to findings table...")
            cur.execute(f"ALTER TABLE findings ADD COLUMN {col} {col_type}")

    conn.commit()
    conn.close()


def create_scan(target, status="Running"):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO scans (target, status, score, created_at)
        VALUES (?, ?, ?, datetime('now'))
    """, (target, status, 0))
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def update_scan_status(scan_id, status):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))
    conn.commit()
    conn.close()


def update_scan_finished(scan_id, score):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("UPDATE scans SET status=?, score=? WHERE id=?", ("Completed", score, scan_id))
    conn.commit()
    conn.close()


def save_finding(scan_id, page, type_, parameter, evidence, severity, owasp_mapping, recommendation):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO findings (scan_id, page, type, parameter, evidence, severity, owasp_mapping, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (scan_id, page, type_, parameter, evidence, severity, owasp_mapping, recommendation))
    conn.commit()
    conn.close()


def get_findings_for_scan(scan_id):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        SELECT page, type, parameter, evidence, severity, owasp_mapping, recommendation
        FROM findings WHERE scan_id=?
    """, (scan_id,))
    rows = cur.fetchall()
    conn.close()
    return rows
