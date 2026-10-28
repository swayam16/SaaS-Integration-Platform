"""Scheduled reconciliation (EventBridge, every 5 minutes).

Webhooks can be lost: the Apex callout gives up, an org admin disables the trigger for a data
load, or the endpoint is down for longer than the retries last. The reconciler asks Salesforce
what changed since its cursor (SOQL on SystemModstamp, with an overlap window) and enqueues
any record whose Slack copy is missing or older. Because events are idempotent, re-enqueueing a
record that was already synced costs one no-op.
"""

from __future__ import annotations

from ..clock import Clock, iso, parse_iso
from ..salesforce.client import SalesforceClient
from ..store import Store
from .engine import MAPPINGS, SETTINGS

CASE_FIELDS = (
    "Id, CaseNumber, Subject, Status, Priority, Origin, Description, Account.Name, "
    "Owner.Name, SystemModstamp"
)
MESSAGE_FIELDS = "Id, Case__c, Body__c, Author__c, Source__c, SystemModstamp"


def flatten(record: dict) -> dict:
    out = {k: v for k, v in record.items() if k != "attributes" and not isinstance(v, dict)}
    if isinstance(record.get("Account"), dict):
        out["AccountName"] = record["Account"].get("Name")
    if isinstance(record.get("Owner"), dict):
        out["OwnerName"] = record["Owner"].get("Name")
    return out


class Reconciler:
    def __init__(
        self,
        store: Store,
        clock: Clock,
        sf: SalesforceClient,
        queue,
        lookback: float = 3600.0,
        overlap: float = 120.0,
    ):
        self.store, self.clock, self.sf, self.queue = store, clock, sf, queue
        self.lookback, self.overlap = lookback, overlap

    def run(self, full: bool = False) -> dict:
        state = self.store.get(SETTINGS, "reconcile") or {}
        now = self.clock.now()
        since = 0.0 if full else float(state.get("cursor", now - self.lookback))
        since_lit = iso(since).replace(".000Z", "Z")
        enqueued = scanned = 0
        newest = since
        for sobject, fields, prefix, extra in (
            ("Case", CASE_FIELDS, "case", ""),
            ("Case_Message__c", MESSAGE_FIELDS, "msg", " AND Source__c != 'Slack'"),
        ):
            soql = (
                f"SELECT {fields} FROM {sobject} WHERE SystemModstamp > {since_lit}{extra} "
                f"ORDER BY SystemModstamp ASC"
            )
            for rec in self.sf.query(soql, max_records=50_000):
                scanned += 1
                modstamp = rec["SystemModstamp"]
                ts = parse_iso(modstamp)
                newest = max(newest, ts)
                m = self.store.get(MAPPINGS, f"{prefix}:{rec['Id']}")
                if m and m.get("status") == "ACTIVE" and m.get("modstamp", 0) >= ts:
                    continue
                self.queue.send(
                    {
                        "source": "reconciler",
                        "kind": "record_change",
                        "event_id": "",
                        "sobject": sobject,
                        "record_id": rec["Id"],
                        "change_type": "UPDATE",
                        "modstamp": modstamp,
                        "fields": flatten(rec),
                        "received_at": now,
                    }
                )
                enqueued += 1
        self.store.put(
            SETTINGS,
            "reconcile",
            {
                "cursor": max(since, newest - self.overlap),
                "last_run": now,
                "last_enqueued": enqueued,
                "last_scanned": scanned,
            },
        )
        return {"scanned": scanned, "enqueued": enqueued}
