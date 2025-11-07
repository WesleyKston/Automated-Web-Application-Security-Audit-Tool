import sqlite3
conn = sqlite3.connect("audit.db")
cur = conn.cursor()
cur.execute("SELECT severity FROM findings;")
print(cur.fetchall())
