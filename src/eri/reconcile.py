"""Reconciliation: does a (validly signed) result make arithmetic sense?

A valid signature proves *who* sent a result and that it was not changed in
transit. It does not prove the numbers are right. These checks catch device
faults and operator errors; anything that fails goes to human review instead
of into the totals.
"""

from __future__ import annotations

from .config import Election
from .models import ResultPayload


def reconcile(payload: ResultPayload, election: Election) -> list[str]:
    """Return a list of problems. An empty list means the result reconciles."""
    station = election.stations.get(payload.station_id)
    if station is None:
        return [f"station {payload.station_id} is not part of this election"]

    problems: list[str] = []
    expected = set(election.candidates)
    reported = set(payload.votes)
    if missing := sorted(expected - reported):
        problems.append(f"missing candidates: {', '.join(missing)}")
    if extra := sorted(reported - expected):
        problems.append(f"unknown candidates: {', '.join(extra)}")

    if payload.ballots_cast > station.registered_voters:
        problems.append(
            f"ballots cast ({payload.ballots_cast}) exceed registered voters "
            f"({station.registered_voters})"
        )

    counted = sum(payload.votes.values()) + payload.invalid_ballots
    if counted != payload.ballots_cast:
        problems.append(
            f"valid votes + invalid ballots ({counted}) != ballots cast ({payload.ballots_cast})"
        )
    return problems
