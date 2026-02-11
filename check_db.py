import sqlite3
conn = sqlite3.connect('hades_knowledge.db')
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
for table in tables:
    print(table[0])
    cursor.execute(f"PRAGMA table_info({table[0]})")
    cols = cursor.fetchall()
    for col in cols:
        print(f"  - {col[1]} ({col[2]})")
conn.close()
