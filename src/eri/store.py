"""SQLite storage. One connection guarded by a lock: simple and correct for a demo.

See docs/adr/0003-sqlite-single-writer.md for why, and what would change at scale.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .audit import AuditLog

SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    station_id   TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL,
    sequence     INTEGER NOT NULL,
    payload      TEXT NOT NULL,
    signature    TEXT NOT NULL,
    received_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS flagged (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id   TEXT NOT NULL,
    device_id    TEXT NOT NULL,
    reasons      TEXT NOT NULL,
    payload      TEXT NOT NULL,
    signature    TEXT NOT NULL,
    received_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_state (
    device_id     TEXT PRIMARY KEY,
    last_sequence INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS seen_nonces (
    nonce TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq       INTEGER PRIMARY KEY,
    ts        TEXT NOT NULL,
    event     TEXT NOT NULL,
    details   TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None: we manage transactions explicitly with BEGIN/COMMIT.
        self.conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.lock = threading.RLock()
        self.audit = AuditLog(self.conn)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialise writers and make each submission all-or-nothing."""
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        with self.lock:
            yield self.conn

    def close(self) -> None:
        with self.lock:
            self.conn.close()
