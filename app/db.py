"""SQLite connection helper.

The database is opened READ-WRITE: registration inserts rows and the account
change-password flow issues UPDATEs. The change-password UPDATE is built by unsafe
string concatenation on a raw-stored username, which is the intended second-order
SQL injection sink (see app.py).
"""

import os
import sqlite3

# DB lives outside /app so `web` can write it (journal/WAL need a writable dir)
# while the application source under /app stays root-owned and read-only to `web`.
DB_PATH = os.environ.get("SHOPSTACK_DB", "/home/web/shopstack.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
