from eri.crypto import canonical_json, generate_private_key, sign_payload, verify_payload


def test_canonical_json_is_order_independent():
    assert canonical_json({"b": 1, "a": [1, 2]}) == canonical_json({"a": [1, 2], "b": 1})


def test_signature_round_trip():
    key = generate_private_key()
    payload = {"votes": {"A": 1}, "station_id": "S1"}
    assert verify_payload(key.public_key(), payload, sign_payload(key, payload))


def test_modified_payload_fails():
    key = generate_private_key()
    payload = {"votes": {"A": 1}}
    sig = sign_payload(key, payload)
    assert not verify_payload(key.public_key(), {"votes": {"A": 2}}, sig)


def test_other_devices_key_fails():
    a, b = generate_private_key(), generate_private_key()
    payload = {"x": 1}
    assert not verify_payload(b.public_key(), payload, sign_payload(a, payload))


def test_garbage_signature_fails_cleanly():
    key = generate_private_key()
    assert not verify_payload(key.public_key(), {"x": 1}, "not base64!!")
    assert not verify_payload(key.public_key(), {"x": 1}, "")
