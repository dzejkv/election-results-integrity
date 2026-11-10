"""Minimal Prometheus-format metrics, so the system can be watched from outside.

Hand-rolled to keep dependencies small; swapping in `prometheus_client` later is
a drop-in change.
"""

from __future__ import annotations

import threading
from collections import Counter

EVENTS = (
    "result_accepted",
    "result_flagged",
    "rejected_malformed",
    "rejected_unknown_device",
    "rejected_bad_signature",
    "rejected_station_mismatch",
    "rejected_wrong_election",
    "rejected_clock_skew",
    "rejected_replay",
)


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._submissions: Counter[str] = Counter()

    def inc(self, event: str) -> None:
        with self._lock:
            self._submissions[event] += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {e: self._submissions.get(e, 0) for e in EVENTS}

    def render(self, gauges: dict[str, tuple[str, float]]) -> str:
        lines = [
            "# HELP eri_submissions_total Result submissions by outcome.",
            "# TYPE eri_submissions_total counter",
        ]
        for event, n in self.snapshot().items():
            lines.append(f'eri_submissions_total{{outcome="{event}"}} {n}')
        for name, (help_text, value) in gauges.items():
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value:g}")
        return "\n".join(lines) + "\n"
