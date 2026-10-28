"""Sync engine scenarios, each one a way integrations end up writing twice or losing data."""

import json
import random
import threading
import time

import pytest

from syncbridge.salesforce.webhook import sign as sf_sign
from syncbridge.sim.faults import FaultPlan
from syncbridge.sim.harness import CHANNEL, Chaos, ChaosConfig, WorkerCrash
from syncbridge.sync.engine import MAPPINGS, SLACK_INDEX


@pytest.fixture
def ch():
    c = Chaos(ChaosConfig(cases=0, faults=False, seed=3))
    c.connect()
    return c


def deliver_sf(ch, payload):
    body = json.dumps(payload).encode()
    ts = int(ch.clock.now())
    return ch._post(
        "/webhooks/salesforce",
        body,
        {
            "x-syncbridge-timestamp": str(ts),
            "x-syncbridge-signature": sf_sign(ch.sf.webhook_secret, ts, body),
        },
    )


def run_queue(ch, rounds=200):
    for _ in range(rounds):
        if not ch.step():
            break


def posts_for(ch, case_id):
    return ch.slack.posts_by_sync_key[f"case:{case_id}"]


def new_case(ch, **fields):
    rec = ch.sf.create_case(
        {
            "Subject": "Login fails",
            "Priority": "High",
            "AccountName": "Globex",
            "OwnerName": "Priya",
            **fields,
        }
    )
    return rec


def test_case_appears_in_slack_once_and_updates_in_place(ch):
    rec = new_case(ch)
    run_queue(ch)
    assert posts_for(ch, rec["Id"]) == 1
    ch.sf.update_case(rec["Id"], {"Status": "Escalated"})
    run_queue(ch)
    m = ch._slack_message_for(rec["Id"])
    assert m["text"].endswith("[Escalated, High]") and posts_for(ch, rec["Id"]) == 1


def test_duplicate_webhooks_are_absorbed(ch):
    rec = new_case(ch)
    [out] = ch.sf.due_notifications() or [ch.sf.outbox.pop()]
    for _ in range(3):  # Apex callout retried twice
        assert deliver_sf(ch, out.payload) == 202
    run_queue(ch)
    assert posts_for(ch, rec["Id"]) == 1
    assert ch.platform.engine.stats.outcomes["duplicate"] == 2


def test_bad_signature_rejected(ch):
    body = b'{"events": []}'
    assert (
        ch._post(
            "/webhooks/salesforce",
            body,
            {"x-syncbridge-timestamp": "1", "x-syncbridge-signature": "v1=00"},
        )
        == 401
    )


def test_timeout_after_slack_accepted_post_is_not_reposted(ch):
    ch.slack.faults = FaultPlan(timeout_after=1.0, rng=random.Random(1))  # every write times out
    rec = new_case(ch)
    run_queue(ch, 20)
    ch.slack.faults = FaultPlan()
    run_queue(ch)
    assert posts_for(ch, rec["Id"]) == 1
    assert ch.platform.slack.recovered_by_metadata >= 1
    assert ch.store.get(MAPPINGS, f"case:{rec['Id']}")["status"] == "ACTIVE"


def test_crash_after_post_before_recording_is_recovered(ch):
    crashed = {"done": False}

    def crash_once(point):
        if point == "after_slack_post" and not crashed["done"]:
            crashed["done"] = True
            ch.platform.engine.crashing = True
            raise WorkerCrash(point)

    ch.platform.engine.crash_hook = crash_once
    rec = new_case(ch)
    run_queue(ch, 400)  # redelivered after the visibility timeout; leases expire
    assert crashed["done"]
    assert posts_for(ch, rec["Id"]) == 1
    assert ch.store.get(MAPPINGS, f"case:{rec['Id']}")["status"] == "ACTIVE"


def test_reply_in_thread_not_yet_indexed_still_reaches_salesforce(ch):
    rec = new_case(ch)
    run_queue(ch)
    m = ch._slack_message_for(rec["Id"])
    ch.store.delete(SLACK_INDEX, f"{CHANNEL}:{m['ts']}")  # as if the worker died before writing it
    ch.slack.human_reply(CHANNEL, m["ts"], "U00000001", "Customer: still broken")
    run_queue(ch)
    msgs = [x for x in ch.sf.messages.values() if x.get("Source__c") == "Slack"]
    assert [x["Body__c"] for x in msgs] == ["Customer: still broken"]
    assert msgs[0]["Case__c"] == rec["Id"]


def test_reply_edit_and_echo(ch):
    rec = new_case(ch)
    run_queue(ch)
    parent = ch._slack_message_for(rec["Id"])
    reply = ch.slack.human_reply(CHANNEL, parent["ts"], "U00000002", "first")
    run_queue(ch)
    ch.slack.human_edit(CHANNEL, reply["ts"], "second")
    run_queue(ch)
    [msg] = [x for x in ch.sf.messages.values() if x.get("Source__c") == "Slack"]
    assert msg["Body__c"] == "second" and msg["Author__c"] == "Sam Rivera"
    # the Case_Message__c we created came back as a Salesforce change and was not echoed
    assert ch.platform.engine.stats.outcomes["skipped_echo"] >= 1
    assert not any(k.startswith("msg:") for k in ch.slack.posts_by_sync_key)


def test_agent_message_becomes_thread_reply(ch):
    rec = new_case(ch)
    run_queue(ch)
    msg = ch.sf.add_message({"Case__c": rec["Id"], "Author__c": "Priya", "Body__c": "On it"})
    run_queue(ch)
    parent = ch._slack_message_for(rec["Id"])
    [reply_ts] = parent["replies"]
    reply = ch.slack.by_ts[(CHANNEL, reply_ts)]
    assert reply["text"] == "Priya: On it"
    assert reply["metadata"]["event_payload"]["sync_key"] == f"msg:{msg['Id']}"


def test_out_of_order_updates_keep_newest(ch):
    from syncbridge.salesforce.webhook import to_queue_messages

    rec = new_case(ch)
    run_queue(ch)
    ch.sf.update_case(rec["Id"], {"Status": "Working"})
    ch.sf.update_case(rec["Id"], {"Status": "Closed"})
    older, newer = [to_queue_messages(o.payload, 0)[0] for o in ch.sf.outbox]
    ch.sf.outbox.clear()
    assert ch.platform.engine.process(newer)["outcome"] == "updated"
    assert ch.platform.engine.process(older)["outcome"] == "skipped_stale"
    assert ch._slack_message_for(rec["Id"])["text"].endswith("[Closed, High]")


def test_buttons_update_salesforce_and_reject_foreign_messages(ch):
    rec = new_case(ch)
    run_queue(ch)
    m = ch._slack_message_for(rec["Id"])
    ch.slack.click(CHANNEL, m["ts"], "case_close", rec["Id"], "U00000003")
    run_queue(ch)
    assert ch.sf.cases[rec["Id"]]["Status"] == "Closed"
    assert ch.sf.cases[rec["Id"]]["Last_Slack_Actor__c"] == "Riley Okafor"
    assert ch._slack_message_for(rec["Id"])["text"].endswith("[Closed, High]")
    other = ch.slack.bot_post(CHANNEL, "someone else's message")
    ch.slack.click(CHANNEL, other["ts"], "case_reopen", rec["Id"], "U00000003")
    run_queue(ch)
    assert ch.sf.cases[rec["Id"]]["Status"] == "Closed"


def test_reconciler_recovers_lost_webhooks(ch):
    rec = new_case(ch)
    ch.sf.outbox.clear()  # the callout never arrived
    run_queue(ch)
    assert posts_for(ch, rec["Id"]) == 0
    assert ch.platform.reconciler.run(full=True)["enqueued"] == 1
    run_queue(ch)
    assert posts_for(ch, rec["Id"]) == 1
    assert ch.platform.reconciler.run(full=True)["enqueued"] == 0


def test_salesforce_token_refresh(ch):
    ch.sf.tokens.clear()  # access token expired
    rec = new_case(ch)
    ch.slack.human_reply  # noqa: B018
    run_queue(ch)
    parent = ch._slack_message_for(rec["Id"])
    ch.sf.tokens.clear()
    ch.slack.human_reply(CHANNEL, parent["ts"], "U00000001", "needs refresh")
    run_queue(ch)
    assert any(m.get("Body__c") == "needs refresh" for m in ch.sf.messages.values())


def test_concurrent_workers_with_duplicate_deliveries():
    """Eight threads process every notification three times over, concurrently."""
    ch = Chaos(ChaosConfig(cases=0, faults=False, seed=5))
    ch.connect()
    ids = [new_case(ch, Subject=f"case {i}")["Id"] for i in range(120)]
    for cid in ids[::3]:
        ch.sf.update_case(cid, {"Status": "Working"})
    for o in list(ch.sf.outbox):
        for _ in range(3):
            deliver_sf(ch, o.payload)
    ch.sf.outbox.clear()
    stop = threading.Event()

    def ticker():
        while not stop.is_set():
            ch.clock.advance(1.0)
            time.sleep(0.002)

    def worker():
        while not stop.is_set():
            for m in ch.queue.receive(1):
                out = ch.platform.worker.handle(m.body, m.receive_count)
                if out.ack:
                    ch.queue.delete(m)
                elif out.delay is not None:
                    ch.queue.change_visibility(m, min(out.delay, 3))

    threads = [threading.Thread(target=worker) for _ in range(8)] + [
        threading.Thread(target=ticker)
    ]
    for t in threads:
        t.start()
    deadline = time.time() + 60
    while (ch.queue.depth() or ch.sf.outbox) and time.time() < deadline:
        ch.deliver()
        time.sleep(0.01)
    stop.set()
    for t in threads:
        t.join()
    assert ch.queue.depth() == 0
    assert all(posts_for(ch, cid) == 1 for cid in ids)
    for cid in ids[::3]:
        assert ch._slack_message_for(cid)["text"].endswith("[Working, High]")
