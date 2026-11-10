"""The core intake pipeline. Every submission goes through the same ordered checks:

    1. canonicalise          -> rejected_malformed
    2. known device?         -> rejected_unknown_device
    3. signature valid?      -> rejected_bad_signature     (authenticate before parsing)
    4. schema valid?         -> rejected_malformed
    5. device bound here?    -> rejected_station_mismatch
    6. right election?       -> rejected_wrong_election
    7. timestamp sane?       -> rejected_clock_skew
    8. new sequence/nonce?   -> rejected_replay
    9. reconciles?           -> result_flagged (human review, not counted)
   10. first for station?    -> result_flagged (duplicate, not counted)
   11. otherwise             -> result_accepted

Whatever the outcome, exactly one audit entry is written in the same
transaction as the state change, so the log and the data cannot drift apart.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import ValidationError

from .audit import utc_now_iso
from .config import Device, Election, Settings
from .crypto import canonical_json, sha256_hex, verify_payload
from .metrics import Metrics
from .models import Envelope, ResultPayload
from .reconcile import reconcile
from .store import Store

log = logging.getLogger("eri")


@dataclass
class Outcome:
    event: str
    status_code: int
    message: str
    audit: dict[str, Any] = field(default_factory=dict)
    receipt: str | None = None

    def body(self) -> dict[str, Any]:
        status = {
            "result_accepted": "accepted",
            "result_flagged": "flagged",
        }.get(self.event, "rejected")
        out: dict[str, Any] = {"status": status, "reason": self.event, "message": self.message}
        if "reasons" in self.audit:
            out["problems"] = self.audit["reasons"]
        if self.receipt:
            out["receipt"] = self.receipt
        return out


def _short(value: Any, limit: int = 64) -> str | None:
    if value is None:
        return None
    s = value if isinstance(value, str) else repr(value)
    return s[:limit]


class ResultService:
    def __init__(
        self,
        election: Election,
        registry: dict[str, Device],
        store: Store,
        metrics: Metrics,
        settings: Settings,
    ):
        self.election = election
        self.registry = registry
        self.store = store
        self.metrics = metrics
        self.settings = settings

    # ---- intake -----------------------------------------------------------

    def submit(self, envelope: Envelope, client: str | None = None) -> Outcome:
        context: dict[str, Any] = {
            "claimed_device": _short(envelope.payload.get("device_id")),
            "claimed_station": _short(envelope.payload.get("station_id")),
            "client": client,
        }
        with self.store.transaction() as conn:
            outcome = self._evaluate(conn, envelope, context)
            outcome.receipt = self.store.audit.append(outcome.event, {**context, **outcome.audit})

        self.metrics.inc(outcome.event)
        level = logging.INFO if outcome.event.startswith("result_") else logging.WARNING
        log.log(level, json.dumps({"event": outcome.event, **context, "message": outcome.message}))
        return outcome

    def record_malformed_request(self, client: str | None, error_count: int) -> None:
        """Requests FastAPI rejects before they reach `submit` are still audited."""
        with self.store.transaction():
            self.store.audit.append(
                "rejected_malformed",
                {"client": client, "stage": "envelope", "errors": error_count},
            )
        self.metrics.inc("rejected_malformed")

    def _evaluate(self, conn, envelope: Envelope, context: dict[str, Any]) -> Outcome:
        raw = envelope.payload

        # 1. canonical form (also gives us a stable hash of exactly what was sent)
        try:
            payload_bytes = canonical_json(raw)
        except (ValueError, TypeError):
            return Outcome("rejected_malformed", 422, "payload cannot be canonicalised")
        context["payload_sha256"] = sha256_hex(payload_bytes)

        # 2. known device
        device_id = raw.get("device_id")
        device = self.registry.get(device_id) if isinstance(device_id, str) else None
        if device is None:
            return Outcome("rejected_unknown_device", 403, "device is not provisioned")
        context["key_fingerprint"] = device.fingerprint

        # 3. signature, checked over the raw payload before we trust any field in it
        if not verify_payload(device.public_key, raw, envelope.signature):
            return Outcome("rejected_bad_signature", 401, "signature does not match payload")

        # 4. schema
        try:
            payload = ResultPayload.model_validate(raw)
        except ValidationError as exc:
            return Outcome(
                "rejected_malformed", 422, "payload failed validation",
                {"errors": exc.error_count()},
            )

        # 5. device <-> station binding (from provisioning / handover)
        if payload.station_id != device.station_id:
            return Outcome(
                "rejected_station_mismatch", 403,
                f"device is assigned to {device.station_id}",
            )

        # 6. election
        if payload.election_id != self.election.election_id:
            return Outcome("rejected_wrong_election", 400, "result is for a different election")

        # 7. timestamps from the future suggest a misconfigured or spoofed device
        now = datetime.now(timezone.utc)
        if payload.issued_at_dt() > now + timedelta(seconds=self.settings.max_future_skew_seconds):
            return Outcome("rejected_clock_skew", 400, "issued_at is too far in the future")

        # 8. replay protection: sequence must increase per device, nonce must be new
        row = conn.execute(
            "SELECT last_sequence FROM device_state WHERE device_id = ?", (device.device_id,)
        ).fetchone()
        last_seq = row[0] if row else 0
        if payload.sequence <= last_seq:
            return Outcome(
                "rejected_replay", 409, f"sequence {payload.sequence} already used (last {last_seq})",
            )
        if conn.execute("SELECT 1 FROM seen_nonces WHERE nonce = ?", (payload.nonce,)).fetchone():
            return Outcome("rejected_replay", 409, "nonce already used")

        conn.execute(
            "INSERT INTO device_state (device_id, last_sequence) VALUES (?, ?) "
            "ON CONFLICT(device_id) DO UPDATE SET last_sequence = excluded.last_sequence",
            (device.device_id, payload.sequence),
        )
        conn.execute("INSERT INTO seen_nonces (nonce) VALUES (?)", (payload.nonce,))
        context["sequence"] = payload.sequence

        payload_text = payload_bytes.decode("utf-8")
        received_at = utc_now_iso()

        # 9-10. reconciliation and duplicates go to human review, never into totals
        problems = reconcile(payload, self.election)
        already = conn.execute(
            "SELECT 1 FROM results WHERE station_id = ?", (payload.station_id,)
        ).fetchone()
        if already:
            problems.append("station already has an accepted result; corrections need review")
        if problems:
            conn.execute(
                "INSERT INTO flagged (station_id, device_id, reasons, payload, signature, received_at) "
                "VALUES (?,?,?,?,?,?)",
                (payload.station_id, device.device_id, json.dumps(problems), payload_text,
                 envelope.signature, received_at),
            )
            return Outcome(
                "result_flagged", 202, "result stored for human review",
                {"reasons": problems},
            )

        # 11. accept
        conn.execute(
            "INSERT INTO results (station_id, device_id, sequence, payload, signature, received_at) "
            "VALUES (?,?,?,?,?,?)",
            (payload.station_id, device.device_id, payload.sequence, payload_text,
             envelope.signature, received_at),
        )
        return Outcome("result_accepted", 201, "result accepted")

    # ---- read side --------------------------------------------------------

    def totals(self) -> dict[str, Any]:
        with self.store.read() as conn:
            rows = conn.execute("SELECT payload FROM results").fetchall()
            flagged = conn.execute("SELECT COUNT(*) FROM flagged").fetchone()[0]
            entries, head = self.store.audit.head()

        votes = {c: 0 for c in self.election.candidates}
        ballots = invalid = 0
        for (payload_text,) in rows:
            p = json.loads(payload_text)
            ballots += p["ballots_cast"]
            invalid += p["invalid_ballots"]
            for name, n in p["votes"].items():
                votes[name] += n

        valid = sum(votes.values())
        return {
            "election_id": self.election.election_id,
            "name": self.election.name,
            "stations_total": len(self.election.stations),
            "stations_reporting": len(rows),
            "results_under_review": flagged,
            "ballots_cast": ballots,
            "invalid_ballots": invalid,
            "candidates": [
                {
                    "name": name,
                    "votes": n,
                    "share": round(n / valid, 4) if valid else 0.0,
                }
                for name, n in votes.items()
            ],
            "audit": {"entries": entries, "head_hash": head},
            "generated_at": utc_now_iso(),
        }

    def stations(self) -> list[dict[str, Any]]:
        with self.store.read() as conn:
            reported = {r[0] for r in conn.execute("SELECT station_id FROM results")}
            flagged = {r[0] for r in conn.execute("SELECT DISTINCT station_id FROM flagged")}
        out = []
        for sid, s in self.election.stations.items():
            status = "reported" if sid in reported else "under_review" if sid in flagged else "pending"
            out.append({
                "station_id": sid,
                "name": s.name,
                "registered_voters": s.registered_voters,
                "status": status,
                "has_review_items": sid in flagged,
            })
        return out

    def verify_audit(self, expected_head: str | None = None):
        with self.store.read():
            return self.store.audit.verify(expected_head)
