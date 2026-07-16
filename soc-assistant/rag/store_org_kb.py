"""
rag/store_org_kb.py

Store 4 - Org KB (direct record lookup: assets, users, Sigma rules, FP
history in the full design; a minimal assets table for this prototype).

Same two bug fixes as rag/store_ioc.py -- see that module's docstring.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

_DB_PATH = Path(__file__).parent / "db" / "org.db"
_org_kb = None  # lazy singleton, populated by get_org_kb()


def get_org_kb() -> sqlite3.Connection:
    """Return the (lazily-opened, cached) org knowledge base SQLite connection."""
    global _org_kb
    if _org_kb is None:
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _org_kb = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        _org_kb.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                hostname TEXT PRIMARY KEY,
                criticality INTEGER,
                owner TEXT
            )
        ''')
        _org_kb.commit()
    return _org_kb
