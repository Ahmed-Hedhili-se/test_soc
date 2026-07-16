"""
rag/store_ioc.py

Store 3 - IOC database (exact key-value, not vector).

Two bugs fixed relative to the original version:
  1. sqlite3.connect() does NOT create missing parent directories -- if
     rag/db/ doesn't exist yet (e.g. first run, fresh checkout), the
     original unconditional `sqlite3.connect("./rag/db/iocs.db")` at
     import time raised sqlite3.OperationalError. The db directory is now
     created before connecting.
  2. The path was a bare relative string ("./rag/db/iocs.db"), which only
     resolves correctly if the process's current working directory happens
     to be soc-assistant/. It's now built from this file's own location
     (Path(__file__).parent), so it works regardless of caller CWD.

The connection is still opened lazily via get_ioc_db(), consistent with
rag/store_attck.py and rag/store_cti_reports.py, so merely importing this
module has no side effects.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

_DB_PATH = Path(__file__).parent / "db" / "iocs.db"
_ioc_db = None  # lazy singleton, populated by get_ioc_db()


def get_ioc_db() -> sqlite3.Connection:
    """Return the (lazily-opened, cached) IOC SQLite connection."""
    global _ioc_db
    if _ioc_db is None:
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _ioc_db = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        _ioc_db.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY,
                ip TEXT UNIQUE,
                exclusivity TEXT,
                analyst_verified INTEGER DEFAULT 0
            )
        ''')
        _ioc_db.commit()
    return _ioc_db
