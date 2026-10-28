"""OAuth plumbing shared by the Salesforce and Slack connections.

* `TokenVault` keeps each provider's tokens envelope-encrypted in the store and refreshes access
  tokens single-flight: one worker refreshes while the others wait for the new token, so a
  burst of 401s does not turn into a burst of refresh calls (Salesforce rate-limits those).
* `OAuthStates` issues the `state` parameter: random, single-use (consumed with a conditional
  delete), expires after 10 minutes and is bound to the admin who started the flow. For
  Salesforce it also carries the PKCE code verifier.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Callable

from .clock import Clock
from .crypto import Envelope
from .errors import Defer, PermanentError
from .idempotency import RecordLock
from .store import ConditionFailed, Store

TOKENS = "tokens"
STATES = "oauth_states"


class TokenVault:
    def __init__(self, store: Store, envelope: Envelope, clock: Clock):
        self.store, self.envelope, self.clock = store, envelope, clock
        self.locks = RecordLock(store, clock, lease_seconds=20)
        self._cache: dict[str, tuple[int, dict]] = {}

    def _ctx(self, provider: str) -> dict[str, str]:
        return {"purpose": "oauth-token", "provider": provider}

    def save(self, provider: str, tokens: dict, connected_by: str = "") -> None:
        current = self.store.get(TOKENS, provider) or {}
        version = int(current.get("version", 0)) + 1
        blob = self.envelope.encrypt(json.dumps(tokens).encode(), self._ctx(provider))
        meta = {
            k: tokens[k]
            for k in ("instance_url", "team_id", "team_name", "org_id", "bot_user_id", "scope")
            if k in tokens
        }
        self.store.put(
            TOKENS,
            provider,
            {
                "blob": blob,
                "version": version,
                "updated_at": self.clock.now(),
                "connected_by": connected_by or current.get("connected_by", ""),
                "connected_at": current.get("connected_at", self.clock.now()),
                "meta": meta,
            },
        )
        self._cache[provider] = (version, tokens)

    def load(self, provider: str) -> dict:
        item = self.store.get(TOKENS, provider)
        if item is None:
            raise PermanentError(f"{provider} is not connected")
        cached = self._cache.get(provider)
        if cached and cached[0] == item["version"]:
            return cached[1]
        tokens = json.loads(self.envelope.decrypt(item["blob"], self._ctx(provider)))
        self._cache[provider] = (item["version"], tokens)
        return tokens

    def status(self, provider: str) -> dict | None:
        item = self.store.get(TOKENS, provider)
        if item is None:
            return None
        return {
            "connected_at": item.get("connected_at"),
            "connected_by": item.get("connected_by"),
            "updated_at": item.get("updated_at"),
            **item.get("meta", {}),
        }

    def delete(self, provider: str) -> None:
        self.store.delete(TOKENS, provider)
        self._cache.pop(provider, None)

    def refresh(
        self, provider: str, stale_access_token: str, do_refresh: Callable[[dict], dict]
    ) -> dict:
        """Refresh once. If another worker already refreshed (the stored access token differs
        from the one that was rejected), use theirs."""
        current = self.load(provider)
        if current.get("access_token") != stale_access_token:
            return current
        token = self.locks.acquire(f"refresh:{provider}")  # raises Defer if someone else is on it
        try:
            current = self.load(provider)
            if current.get("access_token") != stale_access_token:
                return current
            fresh = {**current, **do_refresh(current)}
            self.save(provider, fresh)
            return fresh
        finally:
            self.locks.release(f"refresh:{provider}", token)


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode()
    return verifier, challenge.rstrip("=")


class OAuthStates:
    TTL = 600

    def __init__(self, store: Store, clock: Clock):
        self.store, self.clock = store, clock

    def issue(self, provider: str, user: str, extra: dict | None = None) -> str:
        state = secrets.token_urlsafe(32)
        now = self.clock.now()
        self.store.put(
            STATES,
            state,
            {"provider": provider, "user": user, "created": now, **(extra or {})},
            [("not_exists",)],
            ttl=now + self.TTL,
        )
        return state

    def consume(self, state: str, provider: str) -> dict:
        item = self.store.get(STATES, state or "-")
        if item is None or item.get("provider") != provider:
            raise PermanentError("invalid or expired OAuth state")
        try:
            self.store.delete(STATES, state, [("exists",)])
        except ConditionFailed:
            raise PermanentError("OAuth state already used") from None
        return item


__all__ = ["TokenVault", "OAuthStates", "pkce_pair", "Defer"]
