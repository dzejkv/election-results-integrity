from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from eri.config import Settings, add_registry_entry
from eri.crypto import generate_private_key, public_key_to_pem
from eri.scanner import build_payload, sign_envelope
from eri.server import create_app

ELECTION = {
    "election_id": "TEST-1",
    "name": "Test Election",
    "candidates": ["A", "B", "C"],
    "stations": {
        "S1": {"name": "Station One", "registered_voters": 100},
        "S2": {"name": "Station Two", "registered_voters": 200},
    },
}


@pytest.fixture
def env(tmp_path: Path):
    election_path = tmp_path / "election.json"
    election_path.write_text(json.dumps(ELECTION))
    registry = tmp_path / "devices.json"

    keys = {}
    for device, station in [("D1", "S1"), ("D2", "S2")]:
        key = generate_private_key()
        add_registry_entry(registry, device, station, public_key_to_pem(key.public_key()))
        keys[device] = key

    settings = Settings(
        db_path=str(tmp_path / "eri.db"),
        election_path=str(election_path),
        registry_path=str(registry),
    )
    app = create_app(settings)
    with TestClient(app) as client:
        yield client, keys, settings


def good_payload(device="D1", station="S1", sequence=1, **overrides):
    fields = dict(
        election_id="TEST-1",
        station_id=station,
        device_id=device,
        sequence=sequence,
        ballots_cast=80,
        invalid_ballots=5,
        votes={"A": 40, "B": 25, "C": 10},
    )
    fields.update(overrides)
    return build_payload(**fields)


def signed(keys, device="D1", **kw):
    return sign_envelope(keys[device], good_payload(device=device, **kw))
