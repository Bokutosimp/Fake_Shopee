"""SQLite connection helper (read-write; the account UPDATE is the 2nd-order SQLi sink)."""

import os
import sqlite3

# DB lives outside /app so `web` can write it; /app stays root-owned, read-only to `web`.
DB_PATH = os.environ.get("SHOPSTACK_DB", "/home/web/shopstack.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
