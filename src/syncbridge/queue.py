"""Work queue. Production uses Amazon SQS (standard queue + redrive policy to a DLQ, consumed by
the worker Lambda). MemoryQueue reproduces SQS delivery semantics for local runs and the failure
harness: at-least-once delivery, visibility timeouts, receive counts, per-message delays,
out-of-order receipt and a dead-letter queue after `max_receives`.
"""

from __future__ import annotations

import json
import random
import threading
import uuid
from dataclasses import dataclass, field, replace

from .clock import Clock


@dataclass
class Message:
    id: str
    body: dict
    receipt: str = ""
    receive_count: int = 0
    visible_at: float = 0.0
    sent_at: float = 0.0


class MemoryQueue:
    def __init__(
        self,
        clock: Clock,
        visibility_timeout: float = 60.0,
        max_receives: int = 8,
        rng: random.Random | None = None,
        shuffle: bool = False,
    ):
        self.clock = clock
        self.visibility_timeout = visibility_timeout
        self.max_receives = max_receives
        self.rng = rng or random.Random(0)
        self.shuffle = shuffle
        self._messages: dict[str, Message] = {}
        self.dlq: list[Message] = []
        self._lock = threading.Lock()
        self.sent = self.received = self.deleted = 0

    def send(self, body: dict, delay: float = 0.0) -> str:
        msg = Message(
            str(uuid.uuid4()),
            json.loads(json.dumps(body)),
            visible_at=self.clock.now() + delay,
            sent_at=self.clock.now(),
        )
        with self._lock:
            self._messages[msg.id] = msg
            self.sent += 1
        return msg.id

    def receive(self, max_messages: int = 10) -> list[Message]:
        now = self.clock.now()
        with self._lock:
            ready = [m for m in self._messages.values() if m.visible_at <= now]
            if self.shuffle:
                self.rng.shuffle(ready)
            else:
                ready.sort(key=lambda m: m.visible_at)
            out = []
            for m in ready:
                if m.receive_count >= self.max_receives:  # SQS redrive policy
                    self.dlq.append(m)
                    del self._messages[m.id]
                    continue
                m.receive_count += 1
                m.receipt = uuid.uuid4().hex
                m.visible_at = now + self.visibility_timeout
                out.append(replace(m))  # each receive gets its own receipt handle
                if len(out) >= max_messages:
                    break
            self.received += len(out)
            return out

    def delete(self, msg: Message) -> None:
        with self._lock:
            current = self._messages.get(msg.id)
            if current is not None and current.receipt == msg.receipt:
                del self._messages[msg.id]
                self.deleted += 1

    def change_visibility(self, msg: Message, delay: float) -> None:
        with self._lock:
            current = self._messages.get(msg.id)
            if current is not None and current.receipt == msg.receipt:
                current.visible_at = self.clock.now() + delay

    def depth(self) -> int:
        with self._lock:
            return len(self._messages)

    def next_visible_at(self) -> float | None:
        with self._lock:
            return min((m.visible_at for m in self._messages.values()), default=None)


class SqsQueue:
    """Producer side for Lambda: webhooks enqueue here; the worker Lambda is fed by an SQS
    event source mapping, so it never polls."""

    def __init__(self, queue_url: str, client=None):
        import boto3

        self.url = queue_url
        self.client = client or boto3.client("sqs")

    def send(self, body: dict, delay: float = 0.0) -> str:
        resp = self.client.send_message(
            QueueUrl=self.url,
            MessageBody=json.dumps(body),
            DelaySeconds=int(min(900, max(0, delay))),
        )
        return resp["MessageId"]


@dataclass
class DeadLetter:
    id: str
    body: dict
    reason: str
    receive_count: int
    created_at: float
    extra: dict = field(default_factory=dict)
