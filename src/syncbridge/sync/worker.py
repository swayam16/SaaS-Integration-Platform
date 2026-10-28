"""Queue consumer: runs the engine on one message and decides what happens to it.

    success                         -> delete (ack)
    Defer (lock held, rate limit,   -> back to the queue with a delay (SQS ChangeMessageVisibility)
           dependency not synced)
    PermanentError                  -> dead-letter record for the console, then delete
    anything else (bug, crash)      -> back to the queue; after max receives, dead-letter

Dead letters are kept in the store (not only in the SQS DLQ) so the admin console can show why
each one failed and replay it. Replaying is safe because processing is idempotent.
"""

from __future__ import annotations

import traceback
import uuid
from dataclasses import dataclass

from ..clock import Clock
from ..errors import Defer, PermanentError
from ..store import Store
from .engine import SyncEngine

DEADLETTERS = "deadletters"


@dataclass
class Outcome:
    ack: bool
    delay: float | None = None
    dead_lettered: bool = False
    error: str = ""
    result: dict | None = None


class Worker:
    def __init__(self, engine: SyncEngine, store: Store, clock: Clock, max_receives: int = 8):
        self.engine, self.store, self.clock = engine, store, clock
        self.max_receives = max_receives
        self.deferred = self.dead_lettered = self.crashed = 0

    def handle(self, body: dict, receive_count: int = 1) -> Outcome:
        try:
            result = self.engine.process(body)
            return Outcome(ack=True, result=result)
        except Defer as exc:
            self.deferred += 1
            if receive_count >= self.max_receives:
                return self._dead_letter(
                    body, f"gave up after {receive_count} attempts: {exc}", receive_count
                )
            # Back off harder on each redelivery, capped at SQS's 12-hour visibility maximum.
            delay = min(43_200.0, max(exc.delay, 2.0**receive_count))
            return Outcome(ack=False, delay=delay, error=str(exc))
        except PermanentError as exc:
            return self._dead_letter(body, str(exc), receive_count)
        except Exception as exc:  # noqa: BLE001 - a crash must never lose the message
            self.crashed += 1
            if receive_count >= self.max_receives:
                return self._dead_letter(
                    body,
                    f"{type(exc).__name__}: {exc}",
                    receive_count,
                    traceback.format_exc(limit=3),
                )
            return Outcome(ack=False, delay=None, error=f"{type(exc).__name__}: {exc}")

    def _dead_letter(self, body: dict, reason: str, receive_count: int, trace: str = "") -> Outcome:
        self.dead_lettered += 1
        now = self.clock.now()
        dl_id = f"{now:017.6f}#{uuid.uuid4().hex[:8]}"
        self.store.put(
            DEADLETTERS,
            dl_id,
            {
                "body": body,
                "reason": reason[:500],
                "receive_count": receive_count,
                "created_at": now,
                "trace": trace[-2000:],
                "summary": summarize(body),
            },
        )
        self.engine._metric("dead_lettered")
        return Outcome(ack=True, dead_lettered=True, error=reason)


def summarize(body: dict) -> str:
    if body.get("source") in ("salesforce", "reconciler"):
        return f"{body.get('sobject')} {body.get('record_id')} -> Slack"
    if body.get("kind") == "message":
        return f"Slack reply {body.get('ts')} -> Case_Message__c"
    return f"Slack {body.get('action_id')} on {body.get('value')} -> Case"


def replay(store: Store, queue, dl_id: str) -> dict:
    item = store.get(DEADLETTERS, dl_id)
    if item is None:
        raise KeyError(dl_id)
    queue.send({**item["body"], "replayed_from": dl_id})
    store.delete(DEADLETTERS, dl_id)
    return item
