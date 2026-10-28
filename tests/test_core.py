import base64
import json
import random

import pytest

from syncbridge.breaker import CircuitBreaker
from syncbridge.clock import VirtualClock, iso, parse_iso
from syncbridge.crypto import Envelope, LocalKeyProvider
from syncbridge.errors import Defer, RateLimited, TransientError
from syncbridge.idempotency import ClaimState, IdempotencyGuard, RecordLock
from syncbridge.queue import MemoryQueue
from syncbridge.retry import RetryPolicy, RetryStats
from syncbridge.salesforce import webhook as sfw
from syncbridge.slack import webhook as slw
from syncbridge.store import ConditionFailed
from syncbridge.store.memory import MemoryStore


@pytest.fixture
def vclock():
    return VirtualClock()


def test_store_conditions_and_ttl(vclock):
    s = MemoryStore(vclock)
    s.put("t", "k", {"a": 1}, [("not_exists",)])
    with pytest.raises(ConditionFailed) as exc:
        s.put("t", "k", {"a": 2}, [("not_exists",)])
    assert exc.value.current == {"a": 1}
    s.update("t", "k", {"a": 2}, [("eq", "a", 1)])
    with pytest.raises(ConditionFailed):
        s.update("t", "k", {"a": 3}, [("eq", "a", 1)])
    s.update("t", "k", {"v": 5}, [("lt_or_missing", "v", 5)])
    with pytest.raises(ConditionFailed):
        s.update("t", "k", {"v": 5}, [("lt_or_missing", "v", 5)])
    s.put("t", "exp", {"x": 1}, ttl=vclock.now() + 10)
    vclock.advance(11)
    assert s.get("t", "exp") is None
    s.put("t", "exp", {"x": 2}, [("not_exists",)])  # expired items count as absent
    assert s.increment("m", "h", "n") == 1 and s.increment("m", "h", "n", 4) == 5


def test_idempotency_guard_dedups_and_recovers_from_crash(vclock):
    store = MemoryStore(vclock)
    g = IdempotencyGuard(store, vclock, lease_seconds=60)
    claim = g.begin("sf:Case:1:t1")
    assert claim.state is ClaimState.ACQUIRED
    with pytest.raises(Defer):  # concurrent duplicate while the first is in flight
        g.begin("sf:Case:1:t1")
    vclock.advance(61)  # first worker crashed; lease expired
    takeover = g.begin("sf:Case:1:t1")
    assert takeover.state is ClaimState.ACQUIRED and takeover.takeover
    g.complete(claim, {"stale": True})  # the dead worker's late completion is ignored
    g.complete(takeover, {"outcome": "created"})
    done = g.begin("sf:Case:1:t1")
    assert done.state is ClaimState.DONE and done.result == {"outcome": "created"}


def test_release_allows_immediate_retry(vclock):
    g = IdempotencyGuard(MemoryStore(vclock), vclock)
    c = g.begin("k")
    g.release(c)
    assert g.begin("k").state is ClaimState.ACQUIRED


def test_record_lock(vclock):
    lock = RecordLock(MemoryStore(vclock), vclock, lease_seconds=30)
    t = lock.acquire("case:1")
    with pytest.raises(Defer):
        lock.acquire("case:1")
    lock.release("case:1", "wrong-token")
    with pytest.raises(Defer):
        lock.acquire("case:1")
    lock.release("case:1", t)
    t2 = lock.acquire("case:1")
    vclock.advance(31)
    assert lock.acquire("case:1") != t2  # expired lease can be taken


def test_retry_policy(vclock):
    policy = RetryPolicy(rng=random.Random(1))
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise TransientError("503")
        return "ok"

    stats = RetryStats()
    assert policy.run(flaky, vclock, stats) == "ok" and stats.retries == 2

    def limited():
        raise RateLimited("429", retry_after=2)

    with pytest.raises(Defer):
        policy.run(limited, vclock)
    with pytest.raises(Defer):  # long Retry-After is handed to the queue, not slept inline
        policy.run(lambda: (_ for _ in ()).throw(RateLimited("429", retry_after=120)), vclock)


def test_retry_recovers_ambiguous_write_instead_of_repeating(vclock):
    policy = RetryPolicy(rng=random.Random(1))
    writes = []

    def post():
        writes.append(1)
        raise TransientError("timeout after commit", ambiguous=True)

    assert policy.run(post, vclock, on_ambiguous=lambda e: "found-it") == "found-it"
    assert len(writes) == 1

    def check_fails(_):
        raise TransientError("history unavailable")

    with pytest.raises(Defer, match="verify"):
        policy.run(post, vclock, on_ambiguous=check_fails)


def test_circuit_breaker(vclock):
    b = CircuitBreaker("Slack", vclock, threshold=3, cooldown=10)
    for _ in range(3):
        b.before_call()
        b.failure()
    with pytest.raises(Defer):
        b.before_call()
    vclock.advance(11)
    b.before_call()  # half-open probe
    b.failure()
    with pytest.raises(Defer):
        b.before_call()
    vclock.advance(11)
    b.before_call()
    b.success()
    assert b.state == "closed"


def test_memory_queue_sqs_semantics(vclock):
    q = MemoryQueue(vclock, visibility_timeout=30, max_receives=2)
    q.send({"n": 1})
    q.send({"n": 2}, delay=100)
    [m] = q.receive()
    assert m.body == {"n": 1} and q.receive() == []  # invisible while in flight
    vclock.advance(31)
    [again] = q.receive()
    assert again.id == m.id and again.receive_count == 2
    q.delete(m)  # stale receipt handle: ignored
    assert q.depth() == 2
    vclock.advance(31)
    q.receive()  # third receive exceeds max_receives -> DLQ
    assert len(q.dlq) == 1 and q.depth() == 1


def test_envelope_encryption_binds_context():
    env = Envelope(LocalKeyProvider(b"k" * 32))
    blob = env.encrypt(b'{"access_token":"x"}', {"purpose": "oauth-token", "provider": "slack"})
    assert (
        env.decrypt(blob, {"purpose": "oauth-token", "provider": "slack"})
        == b'{"access_token":"x"}'
    )
    with pytest.raises(Exception):  # noqa: B017
        env.decrypt(blob, {"purpose": "oauth-token", "provider": "salesforce"})
    blob["ct"] = base64.b64encode(b"tampered" + base64.b64decode(blob["ct"])[8:]).decode()
    with pytest.raises(Exception):  # noqa: B017
        env.decrypt(blob, {"purpose": "oauth-token", "provider": "slack"})


def test_webhook_signatures(vclock):
    now = vclock.now()
    body = b'{"events": []}'
    ts = int(now)
    good = {"x-syncbridge-timestamp": str(ts), "x-syncbridge-signature": sfw.sign("s", ts, body)}
    assert sfw.verify("s", good, body, now)
    assert not sfw.verify("other", good, body, now)
    assert not sfw.verify("s", good, body + b" ", now)
    assert not sfw.verify("s", good, body, now + 301)  # replayed later
    assert not sfw.verify("", good, body, now)
    sh = {"x-slack-request-timestamp": str(ts), "x-slack-signature": slw.sign("s", ts, body)}
    assert slw.verify("s", sh, body, now) and not slw.verify("s", sh, body, now - 400)


def test_slack_event_parsing():
    base = {"type": "event_callback", "event_id": "Ev1", "team_id": "T1"}
    reply = {
        **base,
        "event": {
            "type": "message",
            "channel": "C1",
            "user": "U1",
            "text": "hi",
            "ts": "2.0",
            "thread_ts": "1.0",
        },
    }
    assert slw.event_to_message(reply, 0)["thread_ts"] == "1.0"
    top = {**base, "event": {"type": "message", "channel": "C1", "user": "U1", "ts": "2.0"}}
    assert slw.event_to_message(top, 0) is None
    bot = {**base, "event": {**reply["event"], "bot_id": "B1"}}
    assert slw.event_to_message(bot, 0) is None
    edit = {
        **base,
        "event": {
            "type": "message",
            "subtype": "message_changed",
            "channel": "C1",
            "message": {
                "user": "U1",
                "text": "hi2",
                "ts": "2.0",
                "thread_ts": "1.0",
                "edited": {"ts": "3.0"},
            },
        },
    }
    m = slw.event_to_message(edit, 0)
    assert m["text"] == "hi2" and m["version"] == "3.0"
    form = {
        "payload": json.dumps(
            {
                "type": "block_actions",
                "user": {"id": "U1"},
                "container": {"channel_id": "C1", "message_ts": "1.0"},
                "actions": [
                    {"action_id": "case_close", "value": "500x", "action_ts": "5.0"},
                    {"action_id": "other", "value": "y"},
                ],
            }
        )
    }
    [action] = slw.interaction_to_messages(form, 0)
    assert action["action_id"] == "case_close" and action["message_ts"] == "1.0"


def test_iso_roundtrip():
    assert iso(parse_iso("2026-10-28T14:03:11.123Z")) == "2026-10-28T14:03:11.123Z"
