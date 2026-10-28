"""Inbound change notifications from Salesforce.

The Apex trigger in salesforce/force-app (CaseSyncTrigger + SyncBridgeNotifier) sends record
changes as a signed JSON POST:

    X-SyncBridge-Timestamp: 1793000000
    X-SyncBridge-Signature: v1=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>

    {"orgId": "00D...", "events": [{"eventId": "...", "sobject": "Case", "recordId": "500...",
      "changeType": "UPDATE", "systemModstamp": "2026-10-28T14:03:11.123Z",
      "fields": {...}}]}

The handler verifies the signature and timestamp, then enqueues each event and returns 202. All
real work happens in the worker, so the callout is acknowledged in milliseconds.
"""

from __future__ import annotations

from ..crypto import constant_time_equals, hmac_sha256_hex

SIGNATURE_HEADER = "x-syncbridge-signature"
TIMESTAMP_HEADER = "x-syncbridge-timestamp"
SYNCED_OBJECTS = {"Case", "Case_Message__c"}


def sign(secret: str, timestamp: int, body: bytes) -> str:
    return "v1=" + hmac_sha256_hex(secret, f"{timestamp}.".encode() + body)


def verify(
    secret: str, headers: dict[str, str], body: bytes, now: float, tolerance: int = 300
) -> bool:
    if not secret:
        return False
    sig = headers.get(SIGNATURE_HEADER, "")
    ts = headers.get(TIMESTAMP_HEADER, "")
    if not sig or not ts.isdigit():
        return False
    if abs(now - int(ts)) > tolerance:
        return False
    return constant_time_equals(sign(secret, int(ts), body), sig)


def to_queue_messages(payload: dict, received_at: float) -> list[dict]:
    out = []
    for ev in payload.get("events", []):
        if ev.get("sobject") not in SYNCED_OBJECTS or not ev.get("recordId"):
            continue
        out.append(
            {
                "source": "salesforce",
                "kind": "record_change",
                "event_id": ev.get("eventId", ""),
                "sobject": ev["sobject"],
                "record_id": ev["recordId"],
                "change_type": ev.get("changeType", "UPDATE"),
                "modstamp": ev.get("systemModstamp", ""),
                "fields": ev.get("fields", {}),
                "received_at": received_at,
            }
        )
    return out
