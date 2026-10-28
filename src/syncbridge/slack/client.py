"""Slack Web API client.

chat.postMessage has no idempotency key, so a timeout or 5xx after Slack accepted the message
would, with a naive retry, post the message twice. Every message this integration posts carries
message metadata with a `sync_key` (e.g. `case:500Hs00001XyZab`). `post_once` retries through
`find_by_metadata`: after an ambiguous failure it first looks for a message with that sync_key in
the channel (or thread) and only posts again if none is there.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ..breaker import CircuitBreaker
from ..clock import Clock
from ..errors import AuthExpired, PermanentError, RateLimited, TransientError
from ..oauth import TokenVault
from ..retry import RetryPolicy, RetryStats

PROVIDER = "slack"
METADATA_EVENT = "syncbridge_record"

TRANSIENT_ERRORS = {
    "internal_error",
    "fatal_error",
    "service_unavailable",
    "request_timeout",
    "ratelimited",
}
AUTH_REFRESH_ERRORS = {"token_expired"}
PERMANENT_ERRORS = {
    "invalid_auth",
    "token_revoked",
    "account_inactive",
    "not_authed",
    "channel_not_found",
    "not_in_channel",
    "is_archived",
    "msg_too_long",
    "message_not_found",
    "cant_update_message",
    "invalid_blocks",
    "missing_scope",
    "user_not_found",
}
WRITE_METHODS = {"chat.postMessage", "chat.update"}


class SlackClient:
    def __init__(
        self,
        http: httpx.Client,
        vault: TokenVault,
        api_base: str,
        clock: Clock,
        retry: RetryPolicy | None = None,
        refresher=None,
    ):
        self.http, self.vault, self.clock = http, vault, clock
        self.api_base = api_base.rstrip("/")
        self.retry = retry or RetryPolicy()
        self.refresher = refresher  # callable(tokens) -> tokens, when token rotation is on
        self.breaker = CircuitBreaker("Slack", clock)
        self.stats = RetryStats()
        self.calls = 0
        self.recovered_by_metadata = 0
        self._users: dict[str, dict] = {}

    # --- transport ------------------------------------------------------------------------------

    def _send(self, method: str, payload: dict) -> dict:
        self.breaker.before_call()
        try:
            result = self._send_raw(method, payload)
        except RateLimited:
            raise
        except TransientError:
            self.breaker.failure()
            raise
        self.breaker.success()
        return result

    def _send_raw(self, method: str, payload: dict) -> dict:
        tokens = self.vault.load(PROVIDER)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        url = f"{self.api_base}/{method}"
        self.calls += 1
        write = method in WRITE_METHODS
        try:
            if write:
                resp = self.http.post(
                    url,
                    content=json.dumps(payload),
                    headers={**headers, "Content-Type": "application/json; charset=utf-8"},
                    timeout=10.0,
                )
            else:
                resp = self.http.get(url, params=payload, headers=headers, timeout=10.0)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            raise TransientError(f"connect failed: {exc}") from exc
        except httpx.TransportError as exc:
            raise TransientError(f"{method}: {exc}", ambiguous=write) from exc
        if resp.status_code == 429:
            raise RateLimited(
                f"{method} rate limited", retry_after=float(resp.headers.get("Retry-After", "1"))
            )
        if resp.status_code >= 500:
            raise TransientError(f"{method} HTTP {resp.status_code}", ambiguous=write)
        body = resp.json()
        if body.get("ok"):
            return body
        error = body.get("error", "unknown_error")
        if error in AUTH_REFRESH_ERRORS:
            raise AuthExpired(tokens["access_token"])
        if error in TRANSIENT_ERRORS:
            raise TransientError(f"{method}: {error}", ambiguous=write)
        raise PermanentError(f"{method}: {error}")

    def call(self, method: str, payload: dict, on_ambiguous=None) -> dict:
        def attempt() -> dict:
            try:
                return self._send(method, payload)
            except AuthExpired as exc:
                if self.refresher is None:
                    raise PermanentError("Slack token expired and rotation is not set up") from exc
                self.vault.refresh(PROVIDER, str(exc), self.refresher)
                return self._send(method, payload)

        return self.retry.run(attempt, self.clock, self.stats, on_ambiguous=on_ambiguous)

    # --- API ---------------------------------------------------------------------------------------

    def post_once(
        self,
        channel: str,
        sync_key: str,
        text: str,
        blocks: list[dict],
        metadata_payload: dict,
        thread_ts: str | None = None,
        search_from: float = 0.0,
    ) -> str:
        """Post a message exactly once. Returns its ts."""
        payload: dict[str, Any] = {
            "channel": channel,
            "text": text,
            "blocks": blocks,
            "unfurl_links": False,
            "metadata": {
                "event_type": METADATA_EVENT,
                "event_payload": {"sync_key": sync_key, **metadata_payload},
            },
        }
        if thread_ts:
            payload["thread_ts"] = thread_ts

        def recover(_exc: Exception) -> dict | None:
            ts = self.find_by_metadata(channel, sync_key, search_from, thread_ts)
            if ts:
                self.recovered_by_metadata += 1
                return {"ts": ts}
            return None

        return self.call("chat.postMessage", payload, on_ambiguous=recover)["ts"]

    def update(
        self,
        channel: str,
        ts: str,
        text: str,
        blocks: list[dict],
        metadata_payload: dict,
        sync_key: str,
    ) -> None:
        self.call(
            "chat.update",
            {
                "channel": channel,
                "ts": ts,
                "text": text,
                "blocks": blocks,
                "metadata": {
                    "event_type": METADATA_EVENT,
                    "event_payload": {"sync_key": sync_key, **metadata_payload},
                },
            },
        )

    def find_by_metadata(
        self, channel: str, sync_key: str, oldest: float = 0.0, thread_ts: str | None = None
    ) -> str | None:
        method = "conversations.replies" if thread_ts else "conversations.history"
        params: dict[str, Any] = {
            "channel": channel,
            "limit": 200,
            "include_all_metadata": "true",
            "oldest": f"{max(0.0, oldest):.6f}",
        }
        if thread_ts:
            params["ts"] = thread_ts
        cursor = None
        for _ in range(50):
            if cursor:
                params["cursor"] = cursor
            body = self.call(method, params)
            for msg in body.get("messages", []):
                meta = msg.get("metadata") or {}
                if (
                    meta.get("event_type") == METADATA_EVENT
                    and meta.get("event_payload", {}).get("sync_key") == sync_key
                ):
                    return msg["ts"]
            cursor = (body.get("response_metadata") or {}).get("next_cursor")
            if not cursor:
                return None
        return None

    def message_metadata(self, channel: str, ts: str) -> dict | None:
        """Our metadata payload on one top-level message, or None if it isn't ours."""
        body = self.call(
            "conversations.history",
            {
                "channel": channel,
                "latest": ts,
                "inclusive": "true",
                "limit": 1,
                "include_all_metadata": "true",
            },
        )
        for msg in body.get("messages", []):
            meta = msg.get("metadata") or {}
            if msg.get("ts") == ts and meta.get("event_type") == METADATA_EVENT:
                return meta.get("event_payload") or {}
        return None

    def user_info(self, user_id: str) -> dict:
        if user_id not in self._users:
            try:
                user = self.call("users.info", {"user": user_id})["user"]
            except PermanentError:
                user = {"id": user_id, "name": user_id, "profile": {}}
            profile = user.get("profile", {})
            self._users[user_id] = {
                "id": user_id,
                "name": profile.get("real_name") or profile.get("display_name") or user.get("name"),
                "email": profile.get("email", ""),
            }
        return self._users[user_id]
