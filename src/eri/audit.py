"""Tamper-evident audit log (hash chain).

Every entry stores the hash of the previous entry, and its own hash covers its
content plus that link. Editing, inserting or deleting any entry in the middle
breaks the chain from that point on, and `verify()` reports where.

Limitation (see docs/threat-model.md): someone with write access could drop
entries from the *end* or rebuild the whole chain. That is why the current
head hash is published on the public dashboard: anyone who wrote it down can
later check the log with `--expect-head`.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .crypto import canonical_json, sha256_hex

GENESIS_HASH = "0" * 64


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def entry_hash(seq: int, ts: str, event: str, details: dict[str, Any], prev_hash: str) -> str:
    return sha256_hex(
        canonical_json(
            {"seq": seq, "ts": ts, "event": event, "details": details, "prev_hash": prev_hash}
        )
    )


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    head_hash: str
    first_bad_seq: int | None = None
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": self.entries,
            "head_hash": self.head_hash,
            "first_bad_seq": self.first_bad_seq,
            "reason": self.reason,
        }


class AuditLog:
    """Append-only log stored in the `audit_log` table.

    Not thread-safe by itself: the caller (Store) serialises access.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def head(self) -> tuple[int, str]:
        row = self.conn.execute(
            "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (row[0], row[1]) if row else (0, GENESIS_HASH)

    def append(self, event: str, details: dict[str, Any]) -> str:
        last_seq, prev_hash = self.head()
        seq = last_seq + 1
        ts = utc_now_iso()
        h = entry_hash(seq, ts, event, details, prev_hash)
        self.conn.execute(
            "INSERT INTO audit_log (seq, ts, event, details, prev_hash, hash) VALUES (?,?,?,?,?,?)",
            (seq, ts, event, canonical_json(details).decode("utf-8"), prev_hash, h),
        )
        return h

    def verify(self, expected_head: str | None = None) -> VerifyResult:
        return verify_rows(
            self.conn.execute(
                "SELECT seq, ts, event, details, prev_hash, hash FROM audit_log ORDER BY seq"
            ),
            expected_head,
        )


def verify_rows(rows, expected_head: str | None = None) -> VerifyResult:
    expected_prev = GENESIS_HASH
    expected_seq = 1
    count = 0
    for seq, ts, event, details_json, prev_hash, stored_hash in rows:
        if seq != expected_seq:
            return VerifyResult(False, count, expected_prev, expected_seq, "missing or reordered entry")
        if prev_hash != expected_prev:
            return VerifyResult(False, count, expected_prev, seq, "broken link to previous entry")
        try:
            details = json.loads(details_json)
        except json.JSONDecodeError:
            return VerifyResult(False, count, expected_prev, seq, "entry details are not valid JSON")
        if entry_hash(seq, ts, event, details, prev_hash) != stored_hash:
            return VerifyResult(False, count, expected_prev, seq, "entry content was modified")
        expected_prev = stored_hash
        expected_seq += 1
        count += 1
    if expected_head is not None and expected_head != expected_prev:
        return VerifyResult(
            False, count, expected_prev, None, "head does not match the published checkpoint"
        )
    return VerifyResult(True, count, expected_prev)


def main(argv: list[str] | None = None) -> int:
    """`eri-audit verify --db data/eri.db [--expect-head HASH]` - offline, read-only check."""
    parser = argparse.ArgumentParser(prog="eri-audit", description="Verify or print the audit log.")
    parser.add_argument("command", choices=["verify", "show"])
    parser.add_argument("--db", default="data/eri.db")
    parser.add_argument("--expect-head", help="head hash published earlier (e.g. from the dashboard)")
    args = parser.parse_args(argv)

    db = Path(args.db).resolve()
    if not db.exists():
        print(f"database not found: {db}", file=sys.stderr)
        return 2
    conn = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT seq, ts, event, details, prev_hash, hash FROM audit_log ORDER BY seq"
        ).fetchall()
    finally:
        conn.close()

    if args.command == "show":
        for seq, ts, event, details, _prev, h in rows:
            print(f"{seq:>5}  {ts}  {event:<28} {h[:12]}  {details}")
        return 0

    result = verify_rows(rows, args.expect_head)
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
