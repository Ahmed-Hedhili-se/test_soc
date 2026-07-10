import sqlite3

# Store 4 - Org KB (direct record lookup)
# For prototype, a simple SQLite connection or JSON dict can work
org_kb = sqlite3.connect("./rag/db/org.db", check_same_thread=False)

def init_db():
    org_kb.execute('''
        CREATE TABLE IF NOT EXISTS assets (
            hostname TEXT PRIMARY KEY,
            criticality INTEGER,
            owner TEXT
        )
    ''')
    org_kb.commit()

init_db()
