
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "app.db"

schema = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT
);

INSERT OR IGNORE INTO users (id, username, password)
VALUES (1, 'admin', 'admin');

INSERT OR IGNORE INTO items (id, name, description) VALUES
(1, 'apple', 'red and juicy'),
(2, 'banana', 'yellow fruit'),
(3, 'carrot', 'orange and crunchy');
"""

def main():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(schema)
        conn.commit()
        print(f"DB initialized at {DB_PATH}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
