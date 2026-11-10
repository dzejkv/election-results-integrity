import json

from eri.config import Election
from eri.models import ResultPayload
from eri.reconcile import reconcile

from .conftest import ELECTION, good_payload


def election(tmp_path):
    p = tmp_path / "e.json"
    p.write_text(json.dumps(ELECTION))
    return Election.load(p)


def check(tmp_path, **overrides):
    return reconcile(ResultPayload.model_validate(good_payload(**overrides)), election(tmp_path))


def test_consistent_result_has_no_problems(tmp_path):
    assert check(tmp_path) == []


def test_sum_mismatch(tmp_path):
    problems = check(tmp_path, ballots_cast=90)
    assert any("!= ballots cast" in p for p in problems)


def test_more_ballots_than_registered(tmp_path):
    problems = check(tmp_path, ballots_cast=150, invalid_ballots=0, votes={"A": 150, "B": 0, "C": 0})
    assert any("exceed registered voters" in p for p in problems)


def test_missing_and_unknown_candidates(tmp_path):
    problems = check(tmp_path, ballots_cast=70, invalid_ballots=5, votes={"A": 40, "Z": 25})
    assert any("missing candidates: B, C" in p for p in problems)
    assert any("unknown candidates: Z" in p for p in problems)
