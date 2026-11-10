"""Configuration: the election definition, the device registry and runtime settings.

The election definition (candidates, stations, registered voters) is the
server's source of truth. Devices never tell the server how many voters are
registered; they only report what they counted.

The device registry is the output of the provisioning step: which device is
assigned to which station, and its public key. In a real deployment this is
the digital side of the chain-of-custody / handover record.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import fingerprint, load_public_key


@dataclass(frozen=True)
class Station:
    station_id: str
    name: str
    registered_voters: int


@dataclass(frozen=True)
class Election:
    election_id: str
    name: str
    candidates: tuple[str, ...]
    stations: dict[str, Station] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "Election":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        stations = {
            sid: Station(sid, s["name"], int(s["registered_voters"]))
            for sid, s in raw["stations"].items()
        }
        candidates = tuple(raw["candidates"])
        if len(set(candidates)) != len(candidates):
            raise ValueError("duplicate candidate names in election config")
        return cls(raw["election_id"], raw["name"], candidates, stations)

    def public_view(self) -> dict:
        return {
            "election_id": self.election_id,
            "name": self.name,
            "candidates": list(self.candidates),
            "stations": {
                sid: {"name": s.name, "registered_voters": s.registered_voters}
                for sid, s in self.stations.items()
            },
        }


@dataclass(frozen=True)
class Device:
    device_id: str
    station_id: str
    public_key: Ed25519PublicKey
    fingerprint: str


def load_registry(path: str | Path) -> dict[str, Device]:
    """Load provisioned devices. A missing file means no devices are trusted yet."""
    p = Path(path)
    if not p.exists():
        return {}
    raw = json.loads(p.read_text(encoding="utf-8"))
    devices: dict[str, Device] = {}
    for device_id, entry in raw.get("devices", {}).items():
        key = load_public_key(entry["public_key"])
        devices[device_id] = Device(device_id, entry["station_id"], key, fingerprint(key))
    return devices


def add_registry_entry(path: str | Path, device_id: str, station_id: str, public_pem: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    raw = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"devices": {}}
    if device_id in raw["devices"]:
        raise ValueError(f"device {device_id} is already provisioned")
    raw["devices"][device_id] = {"station_id": station_id, "public_key": public_pem}
    p.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class Settings:
    db_path: str = "data/eri.db"
    election_path: str = "config/election.json"
    registry_path: str = "config/devices.json"
    # How far in the future a result's timestamp may be before we reject it.
    max_future_skew_seconds: int = 300

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            db_path=os.environ.get("ERI_DB", cls.db_path),
            election_path=os.environ.get("ERI_ELECTION", cls.election_path),
            registry_path=os.environ.get("ERI_REGISTRY", cls.registry_path),
            max_future_skew_seconds=int(
                os.environ.get("ERI_MAX_FUTURE_SKEW", cls.max_future_skew_seconds)
            ),
        )
