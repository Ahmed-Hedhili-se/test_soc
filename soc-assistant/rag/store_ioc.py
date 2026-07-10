import sqlite3

# Store 3 - IOC database (exact key-value, not vector)
ioc_db = sqlite3.connect("./rag/db/iocs.db", check_same_thread=False)

def init_db():
    ioc_db.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY,
            ip TEXT UNIQUE,
            exclusivity TEXT,
            analyst_verified INTEGER DEFAULT 0
        )
    ''')
    ioc_db.commit()

init_db()
