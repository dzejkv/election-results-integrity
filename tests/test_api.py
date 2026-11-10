import copy
from datetime import datetime, timedelta, timezone

from eri.scanner import sign_envelope

from .conftest import good_payload, signed


def post(client, envelope):
    return client.post("/api/results", json=envelope)


def test_valid_result_is_accepted_and_counted(env):
    client, keys, _ = env
    r = post(client, signed(keys))
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "accepted"
    assert len(r.json()["receipt"]) == 64

    totals = client.get("/api/totals").json()
    assert totals["stations_reporting"] == 1
    assert totals["ballots_cast"] == 80
    assert {c["name"]: c["votes"] for c in totals["candidates"]} == {"A": 40, "B": 25, "C": 10}


def test_tampered_result_is_rejected(env):
    client, keys, _ = env
    envelope = signed(keys)
    envelope["payload"]["votes"]["A"] += 100
    r = post(client, envelope)
    assert r.status_code == 401
    assert r.json()["reason"] == "rejected_bad_signature"
    assert client.get("/api/totals").json()["stations_reporting"] == 0


def test_unknown_device_is_rejected(env):
    client, keys, _ = env
    envelope = sign_envelope(keys["D1"], good_payload(device="ROGUE"))
    assert post(client, envelope).status_code == 403


def test_device_cannot_report_for_another_station(env):
    client, keys, _ = env
    r = post(client, signed(keys, device="D1", station="S2"))
    assert r.status_code == 403
    assert r.json()["reason"] == "rejected_station_mismatch"


def test_replay_is_rejected(env):
    client, keys, _ = env
    envelope = signed(keys)
    assert post(client, envelope).status_code == 201
    r = post(client, copy.deepcopy(envelope))
    assert r.status_code == 409
    assert r.json()["reason"] == "rejected_replay"


def test_reused_nonce_is_rejected(env):
    client, keys, _ = env
    first = signed(keys, device="D1", nonce="a" * 32)
    second = signed(keys, device="D2", station="S2", nonce="a" * 32)
    assert post(client, first).status_code == 201
    assert post(client, second).status_code == 409


def test_wrong_election_is_rejected(env):
    client, keys, _ = env
    r = post(client, signed(keys, election_id="OTHER"))
    assert r.status_code == 400


def test_future_timestamp_is_rejected(env):
    client, keys, _ = env
    future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    r = post(client, signed(keys, issued_at=future))
    assert r.json()["reason"] == "rejected_clock_skew"


def test_signed_but_inconsistent_result_goes_to_review(env):
    client, keys, _ = env
    r = post(client, signed(keys, ballots_cast=95))
    assert r.status_code == 202
    assert r.json()["status"] == "flagged"
    assert r.json()["problems"]
    totals = client.get("/api/totals").json()
    assert totals["stations_reporting"] == 0
    assert totals["results_under_review"] == 1
    stations = {s["station_id"]: s["status"] for s in client.get("/api/stations").json()}
    assert stations["S1"] == "under_review"


def test_second_result_for_same_station_goes_to_review(env):
    client, keys, _ = env
    assert post(client, signed(keys, sequence=1)).status_code == 201
    r = post(client, signed(keys, sequence=2, votes={"A": 10, "B": 55, "C": 10}))
    assert r.status_code == 202
    # The first, accepted result still stands.
    votes = {c["name"]: c["votes"] for c in client.get("/api/totals").json()["candidates"]}
    assert votes["A"] == 40


def test_type_coercion_is_not_allowed(env):
    client, keys, _ = env
    payload = good_payload()
    payload["ballots_cast"] = "80"
    r = post(client, sign_envelope(keys["D1"], payload))
    assert r.status_code == 422


def test_malformed_envelope_is_audited(env):
    client, _, _ = env
    r = client.post("/api/results", json={"nope": True})
    assert r.status_code == 422
    assert client.get("/api/totals").json()["audit"]["entries"] == 1


def test_every_submission_is_in_a_valid_audit_chain(env):
    client, keys, _ = env
    post(client, signed(keys))                        # accepted
    bad = signed(keys, sequence=2)
    bad["signature"] = bad["signature"][::-1]
    post(client, bad)                                 # bad signature
    post(client, signed(keys, device="D1", station="S2", sequence=3))  # mismatch
    v = client.get("/api/audit/verify").json()
    assert v["ok"] and v["entries"] == 3


def test_metrics_and_security_headers(env):
    client, keys, _ = env
    post(client, signed(keys))
    m = client.get("/metrics").text
    assert 'eri_submissions_total{outcome="result_accepted"} 1' in m
    assert "eri_audit_chain_valid 1" in m
    page = client.get("/")
    assert page.status_code == 200
    assert "default-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["x-content-type-options"] == "nosniff"
