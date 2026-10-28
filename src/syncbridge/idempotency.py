"""Idempotency keys and per-record locks, both built on conditional writes.

IdempotencyGuard
    Each inbound event gets a key derived from what it *means*, not how it arrived:
    `sf:<recordId>:<SystemModstamp>` for a Salesforce change, `slack:<event_id>` for a Slack
    event. Claiming the key is a conditional put; a duplicate delivery (Salesforce retry, Slack
    retry, SQS at-least-once redelivery) finds the key COMPLETED and is acknowledged without
    doing anything. A claim is a lease: if a worker dies mid-way, another worker can take the key
    over once the lease expires.

    The guard alone cannot prevent a duplicate if a worker crashes *after* a write but *before*
    marking the key completed. That is why every write is also idempotent on its own: Salesforce
    writes are upserts by external ID, and Slack posts are reserved in the mapping table first
    and recovered through message metadata (see sync/engine.py).

RecordLock
    Serialises work on one record (e.g. two updates to the same Case arriving at once) so a
    stale update can never overwrite a newer one in Slack.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from enum import Enum

from .clock import Clock
from .errors import Defer
from .store import ConditionFailed, Store

IDEMPOTENCY = "idempotency"
LOCKS = "locks"


class ClaimState(Enum):
    ACQUIRED = "acquired"
    DONE = "done"


@dataclass
class Claim:
    key: str
    state: ClaimState
    token: str = ""
    result: dict | None = None
    takeover: bool = False


class IdempotencyGuard:
    def __init__(
        self,
        store: Store,
        clock: Clock,
        lease_seconds: float = 60.0,
        retention_seconds: float = 7 * 24 * 3600,
    ):
        self.store, self.clock = store, clock
        self.lease, self.retention = lease_seconds, retention_seconds

    def begin(self, key: str) -> Claim:
        now = self.clock.now()
        token = secrets.token_hex(8)
        item = {
            "status": "IN_PROGRESS",
            "token": token,
            "lease_until": now + self.lease,
            "first_seen": now,
            "attempts": 1,
        }
        try:
            self.store.put(IDEMPOTENCY, key, item, [("not_exists",)], ttl=now + self.retention)
            return Claim(key, ClaimState.ACQUIRED, token)
        except ConditionFailed as exc:
            current = exc.current or self.store.get(IDEMPOTENCY, key)
        if current is None:  # expired between the two calls; try once more
            return self.begin(key)
        if current.get("status") == "COMPLETED":
            return Claim(key, ClaimState.DONE, result=current.get("result"))
        if current.get("lease_until", 0) > now:
            raise Defer(
                f"{key} is being processed by another worker",
                delay=max(1.0, current["lease_until"] - now),
            )
        # The previous holder's lease expired (crash or timeout): take the key over.
        try:
            self.store.update(
                IDEMPOTENCY,
                key,
                {
                    "token": token,
                    "lease_until": now + self.lease,
                    "attempts": int(current.get("attempts", 1)) + 1,
                },
                [("eq", "status", "IN_PROGRESS"), ("eq", "token", current.get("token"))],
            )
        except ConditionFailed:
            raise Defer(f"{key} was taken over concurrently", delay=1.0) from None
        return Claim(key, ClaimState.ACQUIRED, token, takeover=True)

    def complete(self, claim: Claim, result: dict | None = None) -> None:
        try:
            self.store.update(
                IDEMPOTENCY,
                claim.key,
                {"status": "COMPLETED", "result": result or {}, "completed_at": self.clock.now()},
                [("eq", "token", claim.token)],
                remove=["lease_until"],
            )
        except ConditionFailed:
            # Our lease expired and someone else took over. The work is done and every write
            # is idempotent, so there is nothing to undo; the other worker will finish too.
            pass

    def release(self, claim: Claim) -> None:
        """Give the key back after a failure so a retry can claim it immediately."""
        try:
            self.store.update(
                IDEMPOTENCY,
                claim.key,
                {"lease_until": 0.0},
                [("eq", "token", claim.token), ("eq", "status", "IN_PROGRESS")],
            )
        except ConditionFailed:
            pass


class RecordLock:
    def __init__(self, store: Store, clock: Clock, lease_seconds: float = 30.0):
        self.store, self.clock, self.lease = store, clock, lease_seconds

    def acquire(self, key: str) -> str:
        now = self.clock.now()
        token = secrets.token_hex(8)
        try:
            self.store.put(
                LOCKS,
                key,
                {"token": token, "until": now + self.lease},
                [("lt_or_missing", "until", now)],
                ttl=now + self.lease + 3600,
            )
        except ConditionFailed as exc:
            until = (exc.current or {}).get("until", now + 1)
            raise Defer(f"record {key} is locked", delay=max(0.5, until - now)) from None
        return token

    def release(self, key: str, token: str) -> None:
        try:
            self.store.delete(LOCKS, key, [("eq", "token", token)])
        except ConditionFailed:
            pass
