"""Inbound Slack requests: Events API callbacks and interactivity (button clicks).

Slack signs every request: X-Slack-Signature = "v0=" + HMAC-SHA256(signing_secret,
"v0:<X-Slack-Request-Timestamp>:<raw body>"). Requests older than five minutes are rejected to
stop replays. Slack expects a 2xx within three seconds and retries up to three times otherwise
(X-Slack-Retry-Num), so the handler only verifies, enqueues and returns 200; retries are
de-duplicated downstream by idempotency key.
"""

from __future__ import annotations

import json

from ..crypto import constant_time_equals, hmac_sha256_hex

IGNORED_SUBTYPES = {
    "bot_message",
    "channel_join",
    "channel_leave",
    "channel_topic",
    "channel_purpose",
    "channel_name",
    "message_deleted",
    "thread_broadcast",
    "pinned_item",
    "unpinned_item",
}


def sign(secret: str, timestamp: int, body: bytes) -> str:
    return "v0=" + hmac_sha256_hex(secret, f"v0:{timestamp}:".encode() + body)


def verify(
    secret: str, headers: dict[str, str], body: bytes, now: float, tolerance: int = 300
) -> bool:
    if not secret:
        return False
    ts = headers.get("x-slack-request-timestamp", "")
    sig = headers.get("x-slack-signature", "")
    if not ts.isdigit() or not sig:
        return False
    if abs(now - int(ts)) > tolerance:
        return False
    return constant_time_equals(sign(secret, int(ts), body), sig)


def event_to_message(payload: dict, received_at: float) -> dict | None:
    """Turn an event_callback into a queue message, or None if it is not one we sync."""
    event = payload.get("event") or {}
    if event.get("type") != "message":
        return None
    subtype = event.get("subtype")
    if subtype in IGNORED_SUBTYPES:
        return None
    if subtype == "message_changed":
        inner = event.get("message") or {}
        if inner.get("bot_id"):
            return None
        msg = {
            "user": inner.get("user"),
            "text": inner.get("text", ""),
            "ts": inner.get("ts"),
            "thread_ts": inner.get("thread_ts"),
            "version": (inner.get("edited") or {}).get("ts") or event.get("event_ts"),
        }
    else:
        if event.get("bot_id") or subtype is not None:
            return None  # our own posts come back as events; never sync them back
        msg = {
            "user": event.get("user"),
            "text": event.get("text", ""),
            "ts": event.get("ts"),
            "thread_ts": event.get("thread_ts"),
            "version": event.get("ts"),
        }
    if not msg["thread_ts"] or msg["thread_ts"] == msg["ts"]:
        return None  # only replies inside a synced case thread become case messages
    return {
        "source": "slack",
        "kind": "message",
        "event_id": payload.get("event_id", ""),
        "team_id": payload.get("team_id", ""),
        "channel": event.get("channel"),
        **msg,
        "received_at": received_at,
    }


def interaction_to_messages(form: dict[str, str], received_at: float) -> list[dict]:
    payload = json.loads(form.get("payload", "{}"))
    if payload.get("type") != "block_actions":
        return []
    container = payload.get("container") or {}
    out = []
    for action in payload.get("actions", []):
        if not str(action.get("action_id", "")).startswith("case_"):
            continue
        out.append(
            {
                "source": "slack",
                "kind": "action",
                "action_id": action["action_id"],
                "value": action.get("value", ""),
                "action_ts": action.get("action_ts", ""),
                "user": (payload.get("user") or {}).get("id", ""),
                "channel": container.get("channel_id") or (payload.get("channel") or {}).get("id"),
                "message_ts": container.get("message_ts"),
                "received_at": received_at,
            }
        )
    return out
