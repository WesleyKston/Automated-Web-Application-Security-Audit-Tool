# patch_db.py
import sqlite3
DB = "audit.db"

conn = sqlite3.connect(DB)
cur = conn.cursor()

# create missing tables if needed
cur.execute("PRAGMA table_info(scans)")
cols = [r[1] for r in cur.fetchall()]
if "status" not in cols:
    try:
        cur.execute("ALTER TABLE scans ADD COLUMN status TEXT DEFAULT 'Completed'")
        print("Added status column to scans")
    except Exception as e:
        print("Could not add column (may already exist):", e)

# ensure findings table has owasp_mapping column
cur.execute("PRAGMA table_info(findings)")
cols2 = [r[1] for r in cur.fetchall()]
if "owasp_mapping" not in cols2:
    try:
        cur.execute("ALTER TABLE findings ADD COLUMN owasp_mapping TEXT DEFAULT 'N/A'")
        print("Added owasp_mapping column to findings")
    except Exception as e:
        print("Could not add column (may already exist):", e)

conn.commit()
conn.close()
print("Patch complete.")
