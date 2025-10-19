import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(__file__).resolve().parents[1] / "app.db"


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def query(sql: str, pattern: tuple[str, ...] = tuple()) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        if pattern:
            rows = conn.execute(sql, pattern).fetchall()
        else:
            rows = conn.execute(sql).fetchall()
        return [dict(r) for r in rows]


def query_one(sql: str, pattern: tuple[str, ...] = tuple()) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        if pattern:
            row = conn.execute(sql, pattern).fetchone()
        else:
            row = conn.execute(sql).fetchone()
        return dict(row) if row else None
