"""The sync engine: turns one queued event into the right Salesforce or Slack write, exactly once.

Directions
    Salesforce -> Slack   Case created/updated      -> one channel message per Case, updated in place
                          Case_Message__c (agent)   -> one thread reply per message
    Slack -> Salesforce   thread reply / edit       -> Case_Message__c upsert (external ID = channel:ts)
                          button (escalate/close)   -> PATCH Case

How duplicates are prevented, layer by layer
    1. Idempotency key per event meaning (sf:<object>:<id>:<SystemModstamp>, slack:msg:<ch>:<ts>:<ver>,
       slack:action:<action_ts>:<user>) absorbs Salesforce callout retries, Slack event retries
       and SQS redeliveries.
    2. A per-record lock serialises concurrent events for the same record.
    3. Version guards (SystemModstamp, Slack edit ts, action_ts) drop stale, out-of-order events.
    4. Writes are idempotent themselves: Salesforce upsert by external ID; Slack posts are reserved
       as PENDING in the mapping table before posting and recovered via message metadata if a
       crash or ambiguous error leaves us unsure whether the post happened.
    5. Echo suppression: our own Slack posts and Case_Message__c records that came from Slack are
       never synced back.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..clock import Clock, parse_iso
from ..errors import Defer, PermanentError
from ..idempotency import ClaimState, IdempotencyGuard, RecordLock
from ..salesforce.client import SalesforceClient
from ..slack.blocks import content_hash, render_case, render_case_message
from ..slack.client import SlackClient
from ..store import ConditionFailed, Store

MAPPINGS = "mappings"  # sync_key -> Slack message for a Salesforce record
SLACK_INDEX = "slack_index"  # "<channel>:<ts>" -> sync_key (reverse lookup for threads/buttons)
SLACK_MSGS = "slack_msgs"  # "<channel>:<ts>" -> Case_Message__c synced from Slack
SETTINGS = "settings"
METRICS = "metrics"
ACTIVITY = "activity"

ACTIONS = {
    "case_escalate": {"Status": "Escalated", "Priority": "High"},
    "case_close": {"Status": "Closed"},
    "case_reopen": {"Status": "Working"},
}


@dataclass
class EngineStats:
    outcomes: dict[str, int] = field(default_factory=dict)

    def add(self, outcome: str) -> None:
        self.outcomes[outcome] = self.outcomes.get(outcome, 0) + 1


class SyncEngine:
    def __init__(
        self,
        store: Store,
        clock: Clock,
        sf: SalesforceClient,
        slack: SlackClient,
        *,
        naive: bool = False,
        record_activity: bool = True,
        crash_hook=None,
    ):
        self.store, self.clock, self.sf, self.slack = store, clock, sf, slack
        self.guard = IdempotencyGuard(store, clock)
        self.locks = RecordLock(store, clock)
        self.naive = naive
        self.record_activity = record_activity
        self.crash_hook = crash_hook or (lambda point: None)  # failure-injection seam
        self.crashing = False  # set by the harness when it simulates a hard crash
        self.stats = EngineStats()

    # --- entry point -----------------------------------------------------------------------------

    def process(self, body: dict) -> dict:
        started = self.clock.now()
        key = self.idempotency_key(body)
        claim = None
        if not self.naive:
            claim = self.guard.begin(key)
            if claim.state is ClaimState.DONE:
                self.stats.add("duplicate")
                self._metric("duplicates_suppressed")
                return {"outcome": "duplicate", "key": key}
        try:
            result = self._dispatch(body)
        except Exception:
            if claim is not None:
                self.guard.release(claim)
            raise
        self.crash_hook("before_complete")
        if claim is not None:
            self.guard.complete(claim, result)
        self.stats.add(result["outcome"])
        self._record(body, result, started)
        return result

    @staticmethod
    def idempotency_key(body: dict) -> str:
        if body["source"] in ("salesforce", "reconciler"):
            return f"sf:{body['sobject']}:{body['record_id']}:{body['modstamp']}"
        if body["kind"] == "message":
            return f"slack:msg:{body['channel']}:{body['ts']}:{body.get('version', '')}"
        return f"slack:action:{body['action_ts']}:{body['user']}"

    def _dispatch(self, body: dict) -> dict:
        if body["source"] in ("salesforce", "reconciler"):
            if body["sobject"] == "Case":
                return self.case_to_slack(body)
            return self.case_message_to_slack(body)
        if body["kind"] == "message":
            return self.slack_message_to_salesforce(body)
        return self.slack_action_to_salesforce(body)

    # --- settings ---------------------------------------------------------------------------------

    def settings(self) -> dict:
        s = self.store.get(SETTINGS, "sync") or {}
        if not s.get("channel_id"):
            raise PermanentError("no Slack channel configured (Settings > Slack channel)")
        return s

    # --- Salesforce -> Slack -------------------------------------------------------------------------

    def case_to_slack(self, body: dict) -> dict:
        fields = {**body["fields"], "Id": body["record_id"]}
        modstamp = parse_iso(body["modstamp"])
        cfg = self.settings()
        channel = cfg["channel_id"]
        sync_key = f"case:{body['record_id']}"
        record_url = f"{cfg.get('instance_url', '')}/lightning/r/Case/{body['record_id']}/view"
        text, blocks = render_case(fields, record_url)
        rendered = content_hash(text, blocks)
        meta = {"record_id": body["record_id"], "sobject": "Case", "version": body["modstamp"]}
        return self._sync_record_message(
            sync_key,
            channel,
            modstamp,
            text,
            blocks,
            rendered,
            meta,
            thread_ts=None,
            record_id=body["record_id"],
        )

    def case_message_to_slack(self, body: dict) -> dict:
        fields = body["fields"]
        if fields.get("Source__c") == "Slack":
            self._metric("echoes_suppressed")
            return {"outcome": "skipped_echo"}
        parent = self.store.get(MAPPINGS, f"case:{fields.get('Case__c')}")
        if not parent or parent.get("status") != "ACTIVE":
            raise Defer("parent case is not in Slack yet", delay=5.0)
        text, blocks = render_case_message(fields)
        rendered = content_hash(text, blocks)
        meta = {
            "record_id": body["record_id"],
            "sobject": "Case_Message__c",
            "version": body["modstamp"],
        }
        return self._sync_record_message(
            f"msg:{body['record_id']}",
            parent["channel"],
            parse_iso(body["modstamp"]),
            text,
            blocks,
            rendered,
            meta,
            thread_ts=parent["ts"],
            record_id=body["record_id"],
        )

    def _sync_record_message(
        self,
        sync_key: str,
        channel: str,
        modstamp: float,
        text: str,
        blocks: list[dict],
        rendered: str,
        meta: dict,
        thread_ts: str | None,
        record_id: str,
    ) -> dict:
        if self.naive:
            return self._naive_record_message(
                sync_key, channel, modstamp, text, blocks, rendered, meta, thread_ts, record_id
            )
        lock = self.locks.acquire(sync_key)
        try:
            m = self.store.get(MAPPINGS, sync_key)
            if m and m.get("status") == "ACTIVE":
                if m.get("modstamp", 0) >= modstamp:
                    self._metric("stale_skipped")
                    return {"outcome": "skipped_stale"}
                if m.get("rendered_hash") != rendered:
                    self.slack.update(m["channel"], m["ts"], text, blocks, meta, sync_key)
                    self.crash_hook("after_slack_update")
                    outcome = "updated"
                else:
                    outcome = "unchanged"
                self.store.update(
                    MAPPINGS,
                    sync_key,
                    {"modstamp": modstamp, "rendered_hash": rendered},
                    [("eq", "ts", m["ts"])],
                )
                self._metric("sf_to_slack_updates" if outcome == "updated" else "no_op_updates")
                return {"outcome": outcome, "ts": m["ts"]}

            ts = None
            if m is None:
                # Reserve the message before posting so a crash after the post can be recovered.
                self.store.put(
                    MAPPINGS,
                    sync_key,
                    {
                        "status": "PENDING",
                        "channel": channel,
                        "record_id": record_id,
                        "created_at": self.clock.now(),
                        "thread_ts": thread_ts,
                    },
                    [("not_exists",)],
                )
            else:
                # A previous attempt reserved this message and did not finish: did it post?
                ts = self.slack.find_by_metadata(
                    channel, sync_key, m["created_at"] - 120, thread_ts
                )
                if ts:
                    self.slack.recovered_by_metadata += 1
                    self._metric("recovered_after_crash")
            if ts is None:
                self.crash_hook("before_slack_post")
                ts = self.slack.post_once(
                    channel,
                    sync_key,
                    text,
                    blocks,
                    meta,
                    thread_ts,
                    search_from=(m or {}).get("created_at", self.clock.now()) - 120,
                )
                self.crash_hook("after_slack_post")
            elif m and m.get("rendered_hash") != rendered:
                self.slack.update(channel, ts, text, blocks, meta, sync_key)
            self.store.update(
                MAPPINGS,
                sync_key,
                {
                    "status": "ACTIVE",
                    "ts": ts,
                    "channel": channel,
                    "modstamp": modstamp,
                    "rendered_hash": rendered,
                    "synced_at": self.clock.now(),
                },
            )
            self.store.put(SLACK_INDEX, f"{channel}:{ts}", {"sync_key": sync_key})
            self._metric("sf_to_slack_creates")
            return {"outcome": "created", "ts": ts}
        finally:
            self._release(sync_key, lock)

    def _naive_record_message(
        self, sync_key, channel, modstamp, text, blocks, rendered, meta, thread_ts, record_id
    ) -> dict:
        """Baseline for the failure harness: check-then-act and blind retries, the way a first
        version of an integration is usually written. Not used in production."""
        m = self.store.get(MAPPINGS, sync_key)
        if m:
            if m.get("modstamp", 0) >= modstamp:
                return {"outcome": "skipped_stale"}
            self.slack.update(m["channel"], m["ts"], text, blocks, meta, sync_key)
            self.store.update(MAPPINGS, sync_key, {"modstamp": modstamp, "rendered_hash": rendered})
            return {"outcome": "updated"}
        self.crash_hook("before_slack_post")
        ts = self.slack.call(
            "chat.postMessage",
            {
                "channel": channel,
                "text": text,
                "blocks": blocks,
                "thread_ts": thread_ts,
                "metadata": {
                    "event_type": "syncbridge_record",
                    "event_payload": {"sync_key": sync_key, **meta},
                },
            },
        )["ts"]
        self.crash_hook("after_slack_post")
        self.store.put(
            MAPPINGS,
            sync_key,
            {
                "status": "ACTIVE",
                "ts": ts,
                "channel": channel,
                "modstamp": modstamp,
                "rendered_hash": rendered,
                "record_id": record_id,
            },
        )
        self.store.put(SLACK_INDEX, f"{channel}:{ts}", {"sync_key": sync_key})
        return {"outcome": "created", "ts": ts}

    # --- Slack -> Salesforce ------------------------------------------------------------------------------

    def _case_for_thread(self, channel: str, thread_ts: str) -> dict | None:
        """The case a Slack thread belongs to. Normally found in our index; if not (the case
        message was posted but the worker died before recording it, and someone replied in that
        window) ask Slack for the parent message's metadata instead of dropping the reply."""
        idx = self.store.get(SLACK_INDEX, f"{channel}:{thread_ts}")
        if idx:
            if not idx["sync_key"].startswith("case:"):
                return None
            return self.store.get(MAPPINGS, idx["sync_key"])
        meta = self.slack.message_metadata(channel, thread_ts)
        if not meta or meta.get("sobject") != "Case" or not meta.get("record_id"):
            return None
        self._metric("threads_resolved_from_metadata")
        return {
            "record_id": meta["record_id"],
            "channel": channel,
            "ts": thread_ts,
            "status": "UNRECORDED",
        }

    def slack_message_to_salesforce(self, body: dict) -> dict:
        parent = self._case_for_thread(body["channel"], body["thread_ts"])
        if parent is None:
            return {"outcome": "ignored_not_case_thread"}
        msg_key = f"{body['channel']}:{body['ts']}"
        version = float(body.get("version") or body["ts"])
        author = self.slack.user_info(body["user"]) if body.get("user") else {"name": "Slack user"}
        fields = {
            "Case__c": parent["record_id"],
            "Body__c": body.get("text", "")[:32000],
            "Author__c": author.get("name") or "Slack user",
            "Source__c": "Slack",
            "Slack_Channel__c": body["channel"],
            "Slack_TS__c": body["ts"],
        }
        if self.naive:
            existing = self.store.get(SLACK_MSGS, msg_key)
            if existing:
                if existing.get("version", 0) >= version:
                    return {"outcome": "skipped_stale"}
                self.sf.update_record("Case_Message__c", existing["sf_id"], fields)
                self.store.update(SLACK_MSGS, msg_key, {"version": version})
                return {"outcome": "updated"}
            self.crash_hook("before_sf_write")
            created = self.sf._call(
                "POST",
                f"{self.sf.base}/sobjects/Case_Message__c",
                json={**fields, "Slack_Message_Key__c": msg_key},
            )
            self.crash_hook("after_sf_write")
            self.store.put(SLACK_MSGS, msg_key, {"version": version, "sf_id": created.get("id")})
            return {"outcome": "created"}

        lock = self.locks.acquire(f"slackmsg:{msg_key}")
        try:
            existing = self.store.get(SLACK_MSGS, msg_key)
            if existing and existing.get("version", 0) >= version:
                self._metric("stale_skipped")
                return {"outcome": "skipped_stale"}
            self.crash_hook("before_sf_write")
            result = self.sf.upsert("Case_Message__c", "Slack_Message_Key__c", msg_key, fields)
            self.crash_hook("after_sf_write")
            self.store.put(
                SLACK_MSGS,
                msg_key,
                {"version": version, "sf_id": result["id"], "case_id": parent["record_id"]},
            )
            self._metric("slack_to_sf_messages")
            return {"outcome": "created" if result["created"] else "updated", "sf_id": result["id"]}
        finally:
            self._release(f"slackmsg:{msg_key}", lock)

    def slack_action_to_salesforce(self, body: dict) -> dict:
        fields = ACTIONS.get(body["action_id"])
        if fields is None:
            return {"outcome": "ignored_unknown_action"}
        sync_key = f"case:{body['value']}"
        m = self.store.get(MAPPINGS, sync_key)
        # Only accept buttons on the message we posted for that same case.
        known = bool(
            m and m.get("ts") == body.get("message_ts") and m.get("channel") == body.get("channel")
        )
        if not known and not (m and m.get("ts")):
            parent = self._case_for_thread(body.get("channel", ""), body.get("message_ts", ""))
            known = bool(parent and parent["record_id"] == body["value"])
        if not known:
            self._metric("rejected_actions")
            return {"outcome": "ignored_unknown_message"}
        actor = self.slack.user_info(body["user"]).get("name") or body["user"]
        action_ts = float(body["action_ts"])
        if self.naive:
            self.sf.update_record("Case", body["value"], {**fields, "Last_Slack_Actor__c": actor})
            return {"outcome": "updated"}
        lock = self.locks.acquire(f"action:{sync_key}")
        try:
            m = self.store.get(MAPPINGS, sync_key) or {}
            if m.get("last_action_ts", 0) >= action_ts:
                self._metric("stale_skipped")
                return {"outcome": "skipped_stale"}
            self.crash_hook("before_sf_write")
            self.sf.update_record("Case", body["value"], {**fields, "Last_Slack_Actor__c": actor})
            self.crash_hook("after_sf_write")
            try:
                self.store.update(
                    MAPPINGS,
                    sync_key,
                    {"last_action_ts": action_ts},
                    [("lt_or_missing", "last_action_ts", action_ts)],
                )
            except ConditionFailed:
                pass
            self._metric("slack_to_sf_actions")
            return {"outcome": "updated"}
        finally:
            self._release(f"action:{sync_key}", lock)

    def _release(self, key: str, token: str) -> None:
        if not self.crashing:  # a killed process never gets to release its lock
            self.locks.release(key, token)

    # --- bookkeeping -----------------------------------------------------------------------------------

    def _metric(self, name: str, amount: int = 1) -> None:
        bucket = time.strftime("%Y-%m-%dT%H", time.gmtime(self.clock.now()))
        self.store.increment(METRICS, bucket, name, amount)

    def _record(self, body: dict, result: dict, started: float) -> None:
        self._metric("events_processed")
        if not self.record_activity:
            return
        now = self.clock.now()
        key = f"{now:017.6f}#{body.get('event_id') or body.get('action_ts') or ''}"
        summary = {
            "direction": "sf_to_slack"
            if body["source"] in ("salesforce", "reconciler")
            else "slack_to_sf",
            "object": body.get("sobject") or body.get("kind"),
            "record": body.get("record_id") or body.get("value") or body.get("ts"),
            "outcome": result["outcome"],
            "at": now,
            "lag_ms": round((now - float(body.get("received_at") or started)) * 1000),
        }
        self.store.put(ACTIVITY, key, summary, ttl=now + 7 * 24 * 3600)
