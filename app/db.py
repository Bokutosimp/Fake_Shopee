"""Read-only SQLite connection helper.

The database is opened in read-only mode so that even a successful SQL injection
cannot mutate state (defense-in-depth on top of GZCTF per-team instancing).
"""

import os
import sqlite3

DB_PATH = os.environ.get("SHOPSTACK_DB", "/app/shopstack.db")


def get_db():
    # Open the DB read-only via a file: URI. mode=ro forbids writes at the VFS
    # layer; PRAGMA query_only=1 is a second, belt-and-suspenders guard.
    uri = f"file:{DB_PATH}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = 1;")
    return conn
