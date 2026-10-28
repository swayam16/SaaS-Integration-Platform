"""Fault plans for the API simulators."""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class FaultPlan:
    """Per-request fault probabilities. "after" faults apply the write and then fail, which is
    the case that produces duplicates in naive integrations."""

    error_before: float = 0.0  # 5xx, nothing applied
    error_after: float = 0.0  # write applied, then 5xx
    timeout_after: float = 0.0  # write applied, response lost (read timeout)
    connect_error: float = 0.0  # never reached the server
    rate_limit: float = 0.0  # 429 / REQUEST_LIMIT_EXCEEDED
    lock_error: float = 0.0  # Salesforce UNABLE_TO_LOCK_ROW
    outages: list[tuple[float, float]] = field(default_factory=list)  # (start, end) virtual time
    rng: random.Random = field(default_factory=lambda: random.Random(1))
    injected: Counter = field(default_factory=Counter)

    def in_outage(self, now: float) -> bool:
        return any(start <= now < end for start, end in self.outages)

    def pick(self, now: float, write: bool) -> str | None:
        if self.in_outage(now):
            self.injected["outage"] += 1
            return "outage"
        r = self.rng.random()
        for name, p, writes_only in (
            ("connect_error", self.connect_error, False),
            ("rate_limit", self.rate_limit, False),
            ("error_before", self.error_before, False),
            ("lock_error", self.lock_error, True),
            ("error_after", self.error_after, True),
            ("timeout_after", self.timeout_after, True),
        ):
            if writes_only and not write:
                continue
            if r < p:
                self.injected[name] += 1
                return name
            r -= p
        return None


@dataclass
class DeliveryPlan:
    """Faults on webhook/event delivery into the platform."""

    duplicate: float = 0.0  # deliver the same notification again (sender retry)
    drop: float = 0.0  # never delivered (only the reconciler can recover these)
    max_delay: float = 0.0  # random extra delay, which reorders deliveries
    rng: random.Random = field(default_factory=lambda: random.Random(2))
    injected: Counter = field(default_factory=Counter)
