"""Time source. Production uses the wall clock; tests and the failure harness use a virtual
clock so retries, leases and visibility timeouts can be exercised without real waiting."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime


class Clock:
    def now(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def iso(self, ts: float | None = None) -> str:
        return iso(self.now() if ts is None else ts)


class VirtualClock(Clock):
    """Deterministic clock: sleep() advances time instantly."""

    def __init__(self, start: float = 1_793_000_000.0):
        self._t = start
        self._lock = threading.Lock()
        self.slept = 0.0

    def now(self) -> float:
        with self._lock:
            return self._t

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            self.advance(seconds)
            self.slept += seconds

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._t += seconds


def iso(ts: float) -> str:
    """Salesforce-style UTC timestamp with milliseconds: 2026-10-28T14:03:11.123Z."""
    dt = datetime.fromtimestamp(ts, tz=UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_iso(value: str) -> float:
    value = value.replace("Z", "+00:00")
    if "+0000" in value:
        value = value.replace("+0000", "+00:00")
    return datetime.fromisoformat(value).timestamp()
