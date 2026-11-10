"""Simulated ballot scanner.

    eri-scanner provision --device SCN-001 --station ST-001
    eri-scanner submit    --device SCN-001 --station ST-001 [--tamper | --replay | --inconsistent]

`provision` plays the role of the device-preparation step: it creates the
device's key pair, keeps the private key on the "device" (a local file) and
records the public key plus station assignment in the server's registry.

`submit` produces fictional, internally consistent counts, signs them and
sends them. The attack flags exist to show that the server catches them.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import secrets
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import add_registry_entry
from .crypto import (
    fingerprint,
    generate_private_key,
    load_private_key,
    private_key_to_pem,
    public_key_to_pem,
    sign_payload,
)


# ---- building blocks (also used by the tests) ------------------------------

def build_payload(
    *,
    election_id: str,
    station_id: str,
    device_id: str,
    sequence: int,
    ballots_cast: int,
    invalid_ballots: int,
    votes: dict[str, int],
    issued_at: str | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    return {
        "version": 1,
        "election_id": election_id,
        "station_id": station_id,
        "device_id": device_id,
        "sequence": sequence,
        "issued_at": issued_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nonce": nonce or secrets.token_hex(16),
        "ballots_cast": ballots_cast,
        "invalid_ballots": invalid_ballots,
        "votes": votes,
    }


def sign_envelope(private_key, payload: dict[str, Any]) -> dict[str, Any]:
    return {"payload": payload, "signature": sign_payload(private_key, payload)}


def simulate_counts(
    candidates: list[str], registered_voters: int, rng: random.Random
) -> tuple[int, int, dict[str, int]]:
    """Fictional counts that always reconcile."""
    ballots = int(registered_voters * rng.uniform(0.45, 0.80))
    invalid = rng.randint(0, max(1, ballots // 40))
    valid = ballots - invalid
    weights = [rng.random() + 0.2 for _ in candidates]
    total_w = sum(weights)
    votes = {c: int(valid * w / total_w) for c, w in zip(candidates, weights)}
    votes[candidates[0]] += valid - sum(votes.values())  # rounding remainder
    return ballots, invalid, votes


# ---- device-side state ----------------------------------------------------

def key_path(keys_dir: Path, device_id: str) -> Path:
    return keys_dir / f"{device_id}.pem"


def provision(device_id: str, station_id: str, keys_dir: Path, registry: Path) -> str:
    keys_dir.mkdir(parents=True, exist_ok=True)
    path = key_path(keys_dir, device_id)
    if path.exists():
        raise SystemExit(f"{path} already exists; refusing to overwrite a device key")
    key = generate_private_key()
    # Create the key file readable only by the owner.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_key_to_pem(key))
    add_registry_entry(registry, device_id, station_id, public_key_to_pem(key.public_key()))
    return fingerprint(key.public_key())


def next_sequence(keys_dir: Path, device_id: str) -> int:
    """Monotonic counter kept on the device, so every submission is unique."""
    path = keys_dir / f"{device_id}.seq"
    seq = int(path.read_text()) + 1 if path.exists() else 1
    path.write_text(str(seq))
    return seq


# ---- HTTP -------------------------------------------------------------------

def http_json(method: str, url: str, body: dict | None = None) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"null")


# ---- CLI --------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eri-scanner", description="Fictional ballot scanner.")
    parser.add_argument("--keys-dir", type=Path, default=Path(os.environ.get("ERI_KEYS", "keys")))
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("provision", help="create a device key and register it")
    p.add_argument("--device", required=True)
    p.add_argument("--station", required=True)
    p.add_argument("--registry", type=Path,
                   default=Path(os.environ.get("ERI_REGISTRY", "config/devices.json")))

    s = sub.add_parser("submit", help="count, sign and send a result")
    s.add_argument("--device", required=True)
    s.add_argument("--station", required=True)
    s.add_argument("--server", default=os.environ.get("ERI_SERVER", "http://127.0.0.1:8000"))
    s.add_argument("--seed", type=int, help="make the fictional counts reproducible")
    attack = s.add_mutually_exclusive_group()
    attack.add_argument("--tamper", action="store_true",
                        help="change a vote count after signing (should be rejected)")
    attack.add_argument("--replay", action="store_true",
                        help="send the same signed result twice (second should be rejected)")
    attack.add_argument("--inconsistent", action="store_true",
                        help="sign numbers that do not add up (should be flagged for review)")

    args = parser.parse_args(argv)

    if args.command == "provision":
        fp = provision(args.device, args.station, args.keys_dir, args.registry)
        print(f"provisioned {args.device} -> {args.station}  key fingerprint {fp}")
        return 0

    key = load_private_key(key_path(args.keys_dir, args.device).read_bytes())
    status, election = http_json("GET", f"{args.server}/api/election")
    if status != 200:
        print(f"could not fetch election definition: HTTP {status}", file=sys.stderr)
        return 1
    station = election["stations"].get(args.station)
    if station is None:
        print(f"unknown station {args.station}", file=sys.stderr)
        return 1

    rng = random.Random(args.seed)
    ballots, invalid, votes = simulate_counts(
        election["candidates"], station["registered_voters"], rng
    )
    if args.inconsistent:
        ballots += 25  # numbers no longer add up, but the device signs them anyway

    payload = build_payload(
        election_id=election["election_id"],
        station_id=args.station,
        device_id=args.device,
        sequence=next_sequence(args.keys_dir, args.device),
        ballots_cast=ballots,
        invalid_ballots=invalid,
        votes=votes,
    )
    envelope = sign_envelope(key, payload)

    if args.tamper:
        first = election["candidates"][0]
        envelope["payload"]["votes"][first] += 100  # modified in transit, after signing

    attempts = 2 if args.replay else 1
    worst = 0
    for i in range(attempts):
        status, body = http_json("POST", f"{args.server}/api/results", envelope)
        label = f"attempt {i + 1}: " if attempts > 1 else ""
        print(f"{label}HTTP {status} {json.dumps(body)}")
        worst = max(worst, status)
    return 0 if worst < 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())
