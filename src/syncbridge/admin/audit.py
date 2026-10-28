"""Append-only audit log of security-relevant actions (logins, provisioning, connections,
settings, dead-letter replays). Kept for a year; readable by admins in the console."""

from __future__ import annotations

import secrets

from ..clock import Clock
from ..store import Store

AUDIT = "audit"
RETENTION = 365 * 24 * 3600


class AuditLog:
    def __init__(self, store: Store, clock: Clock):
        self.store, self.clock = store, clock

    def record(
        self, actor: str, action: str, target: str = "", detail: dict | None = None, ip: str = ""
    ) -> None:
        now = self.clock.now()
        self.store.put(
            AUDIT,
            f"{now:017.6f}#{secrets.token_hex(4)}",
            {
                "at": now,
                "actor": actor,
                "action": action,
                "target": target,
                "detail": detail or {},
                "ip": ip,
            },
            ttl=now + RETENTION,
        )

    def recent(self, limit: int = 100) -> list[dict]:
        return [item for _, item in self.store.list(AUDIT, limit=limit, reverse=True)]
