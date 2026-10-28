"""Circuit breaker per downstream API.

When Salesforce or Slack is down, retrying every queued message against it only adds load and
burns rate-limit budget. After `threshold` consecutive failures the breaker opens: calls are not
made and messages are deferred back to the queue until `cooldown` passes. Then one probe call
is allowed (half-open); success closes the breaker, failure reopens it. Rate limits (429) don't
count as failures: they carry their own Retry-After.

State is per Lambda container; each container learns about an outage within a few calls.
"""

from __future__ import annotations

import threading

from .clock import Clock
from .errors import Defer


class CircuitBreaker:
    def __init__(self, name: str, clock: Clock, threshold: int = 8, cooldown: float = 20.0):
        self.name, self.clock = name, clock
        self.threshold, self.cooldown = threshold, cooldown
        self.failures = 0
        self.open_until = 0.0
        self.half_open = False
        self.opened = 0
        self.short_circuited = 0
        self._lock = threading.Lock()

    def before_call(self) -> None:
        with self._lock:
            now = self.clock.now()
            if now < self.open_until:
                self.short_circuited += 1
                raise Defer(
                    f"{self.name} unavailable (circuit open)", delay=self.open_until - now + 1.0
                )
            if self.open_until and not self.half_open:
                self.half_open = True  # cooldown over: let calls through, watch the first result

    def success(self) -> None:
        with self._lock:
            self.failures = 0
            self.half_open = False
            self.open_until = 0.0

    def failure(self) -> None:
        with self._lock:
            self.failures += 1
            if self.half_open or self.failures >= self.threshold:
                self.open_until = self.clock.now() + self.cooldown
                self.failures = 0
                self.half_open = False
                self.opened += 1

    @property
    def state(self) -> str:
        if self.clock.now() < self.open_until:
            return "open"
        return "half_open" if self.half_open else "closed"
