import json

from eri.audit import main as audit_cli
from eri.store import Store


def make_log(tmp_path, n=5):
    store = Store(tmp_path / "a.db")
    with store.transaction():
        for i in range(n):
            store.audit.append("event", {"i": i})
    return store


def test_intact_chain_verifies(tmp_path):
    store = make_log(tmp_path)
    result = store.audit.verify()
    assert result.ok and result.entries == 5


def test_edited_entry_is_detected(tmp_path):
    store = make_log(tmp_path)
    store.conn.execute("UPDATE audit_log SET details = ? WHERE seq = 3", (json.dumps({"i": 99}),))
    result = store.audit.verify()
    assert not result.ok
    assert result.first_bad_seq == 3
    assert result.reason == "entry content was modified"


def test_deleted_entry_is_detected(tmp_path):
    store = make_log(tmp_path)
    store.conn.execute("DELETE FROM audit_log WHERE seq = 2")
    result = store.audit.verify()
    assert not result.ok and result.first_bad_seq == 2


def test_rehashed_entry_breaks_the_next_link(tmp_path):
    """An attacker who edits an entry AND recomputes its hash still breaks entry n+1."""
    from eri.audit import entry_hash

    store = make_log(tmp_path)
    seq, ts, event, _details, prev, _h = store.conn.execute(
        "SELECT * FROM audit_log WHERE seq = 2"
    ).fetchone()
    forged = {"i": 1000}
    new_hash = entry_hash(seq, ts, event, forged, prev)
    store.conn.execute(
        "UPDATE audit_log SET details = ?, hash = ? WHERE seq = 2", (json.dumps(forged), new_hash)
    )
    result = store.audit.verify()
    assert not result.ok and result.first_bad_seq == 3


def test_truncation_is_caught_by_published_checkpoint(tmp_path):
    store = make_log(tmp_path)
    published = store.audit.head()[1]
    store.conn.execute("DELETE FROM audit_log WHERE seq = 5")
    assert store.audit.verify().ok  # truncation alone is not visible...
    assert not store.audit.verify(expected_head=published).ok  # ...but the checkpoint catches it


def test_cli_exit_codes(tmp_path, capsys):
    store = make_log(tmp_path)
    db = str(tmp_path / "a.db")
    assert audit_cli(["verify", "--db", db]) == 0
    store.conn.execute("UPDATE audit_log SET event = 'x' WHERE seq = 1")
    assert audit_cli(["verify", "--db", db]) == 1
