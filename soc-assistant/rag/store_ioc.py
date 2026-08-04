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
from typing import Optional

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


def get_ioc_exclusivity(ip: str) -> Optional[str]:
    """
    Return the recorded exclusivity ('shared' | 'dedicated') for *ip*, or
    None if it hasn't been classified yet. Used by cti_enrichment to
    discount confidence on shared infrastructure (e.g. a CDN edge IP or
    corporate NAT gateway) that many benign hosts also share.
    """
    db = get_ioc_db()
    row = db.execute("SELECT exclusivity FROM iocs WHERE ip = ?", (ip,)).fetchone()
    return row[0] if row else None


def record_ioc_exclusivity(ip: str, exclusivity: str, analyst_verified: bool = False) -> None:
    """Upsert the exclusivity classification for *ip*."""
    db = get_ioc_db()
    db.execute(
        """
        INSERT INTO iocs (ip, exclusivity, analyst_verified)
        VALUES (?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET exclusivity = excluded.exclusivity,
                                       analyst_verified = excluded.analyst_verified
        """,
        (ip, exclusivity, int(analyst_verified)),
    )
    db.commit()
