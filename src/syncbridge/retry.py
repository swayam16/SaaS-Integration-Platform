"""Retries with exponential backoff, full jitter and Retry-After.

Short waits happen inline. A wait longer than `inline_limit` (a long Retry-After, or a retry
budget that has run out) raises Defer instead, so the message goes back to the queue with a
delay rather than keeping a Lambda invocation alive and billed while it sleeps.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

from .clock import Clock
from .errors import Defer, TransientError

T = TypeVar("T")


@dataclass
class RetryStats:
    attempts: int = 0
    retries: int = 0
    rate_limited: int = 0
    ambiguous: int = 0
    waited: float = 0.0

    def merge(self, other: RetryStats) -> None:
        self.attempts += other.attempts
        self.retries += other.retries
        self.rate_limited += other.rate_limited
        self.ambiguous += other.ambiguous
        self.waited += other.waited


@dataclass
class RetryPolicy:
    max_attempts: int = 5
    base_delay: float = 0.2
    max_delay: float = 8.0
    inline_limit: float = 10.0  # longer waits are handed back to the queue
    budget: float = 20.0  # total inline waiting per call
    rng: random.Random = field(default_factory=random.Random)

    def backoff(self, attempt: int) -> float:
        """Full jitter: uniform(0, min(cap, base * 2^attempt))."""
        return self.rng.uniform(0, min(self.max_delay, self.base_delay * (2**attempt)))

    def run(
        self,
        fn: Callable[[], T],
        clock: Clock,
        stats: RetryStats | None = None,
        on_ambiguous: Callable[[TransientError], T | None] | None = None,
    ) -> T:
        """Call fn until it succeeds. `on_ambiguous` is consulted after a failure that may have
        been applied remotely; returning a value means "it was applied, here is the result"."""
        stats = stats if stats is not None else RetryStats()
        waited = 0.0
        for attempt in range(self.max_attempts):
            stats.attempts += 1
            try:
                return fn()
            except TransientError as exc:
                last = exc
                if exc.ambiguous:
                    stats.ambiguous += 1
                    if on_ambiguous is not None:
                        try:
                            recovered = on_ambiguous(exc)
                        except TransientError as check_exc:
                            # We can't tell whether the write happened, so we must not repeat
                            # it yet. Try the whole message again later.
                            raise Defer(
                                f"could not verify ambiguous write: {check_exc}",
                                delay=max(5.0, check_exc.retry_after or 0),
                            ) from exc
                        if recovered is not None:
                            return recovered
                if exc.retry_after is not None:
                    stats.rate_limited += 1
                    delay = exc.retry_after
                else:
                    delay = self.backoff(attempt)
                if attempt + 1 >= self.max_attempts:
                    break
                if delay > self.inline_limit or waited + delay > self.budget:
                    raise Defer(f"retry later: {exc}", delay=max(delay, 1.0)) from exc
                stats.retries += 1
                stats.waited += delay
                waited += delay
                clock.sleep(delay)
        raise Defer(f"retries exhausted: {last}", delay=30.0) from last
