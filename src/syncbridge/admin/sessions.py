"""Server-side sessions for the admin console.

The cookie holds a random 256-bit ID; the store keys sessions by its SHA-256, so a read of the
table does not yield usable cookies. Sessions are indexed by user so SCIM deactivation (or a
role change) can revoke them immediately. Cookies are HttpOnly, Secure, SameSite=Lax and use the
__Host- prefix in HTTPS deployments. State-changing API calls need the per-session CSRF token
in X-CSRF-Token and a same-origin Origin header.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from ..clock import Clock
from ..config import Settings
from ..crypto import constant_time_equals, sha256_hex
from ..store import Store

SESSIONS = "sessions"
BY_USER = "sessions_by_user"
ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}


@dataclass
class Session:
    id_hash: str
    user_id: str
    email: str
    name: str
    role: str
    csrf: str
    created: float
    expires: float

    def can(self, role: str) -> bool:
        return ROLE_RANK.get(self.role, 0) >= ROLE_RANK[role]


class Sessions:
    def __init__(self, store: Store, clock: Clock, settings: Settings):
        self.store, self.clock, self.s = store, clock, settings

    @property
    def cookie_name(self) -> str:
        return "__Host-sb_session" if self.s.secure_cookies else "sb_session"

    def create(
        self,
        user_id: str,
        email: str,
        name: str,
        role: str,
        idp_session_expiry: float | None = None,
    ) -> tuple[str, Session]:
        now = self.clock.now()
        raw = secrets.token_urlsafe(32)
        h = sha256_hex(raw)
        expires = now + self.s.session_max_seconds
        if idp_session_expiry:
            expires = min(expires, idp_session_expiry)
        sess = Session(h, user_id, email, name, role, secrets.token_urlsafe(24), now, expires)
        self.store.put(
            SESSIONS, h, {**sess.__dict__, "last_seen": now}, [("not_exists",)], ttl=expires
        )
        self.store.put(BY_USER, f"{user_id}#{h}", {"at": now}, ttl=expires)
        return raw, sess

    def cookie(self, raw: str, max_age: int | None = None) -> str:
        attrs = [f"{self.cookie_name}={raw}", "Path=/", "HttpOnly", "SameSite=Lax"]
        if self.s.secure_cookies:
            attrs.append("Secure")
        if max_age is not None:
            attrs.append(f"Max-Age={max_age}")
        return "; ".join(attrs)

    def clear_cookie(self) -> str:
        return self.cookie("", max_age=0)

    def get(self, raw: str | None) -> Session | None:
        if not raw:
            return None
        h = sha256_hex(raw)
        item = self.store.get(SESSIONS, h)
        if item is None:
            return None
        now = self.clock.now()
        if now >= item["expires"] or now - item["last_seen"] > self.s.session_idle_seconds:
            self.destroy_hash(h, item["user_id"])
            return None
        if now - item["last_seen"] > 60:  # sliding idle timeout, written at most once a minute
            self.store.update(SESSIONS, h, {"last_seen": now})
        return Session(
            h,
            item["user_id"],
            item["email"],
            item["name"],
            item["role"],
            item["csrf"],
            item["created"],
            item["expires"],
        )

    def check_csrf(self, sess: Session, token: str) -> bool:
        return bool(token) and constant_time_equals(sess.csrf, token)

    def destroy_hash(self, h: str, user_id: str) -> None:
        self.store.delete(SESSIONS, h)
        self.store.delete(BY_USER, f"{user_id}#{h}")

    def revoke_user(self, user_id: str) -> int:
        n = 0
        for key, _ in self.store.list(BY_USER, prefix=f"{user_id}#"):
            self.destroy_hash(key.split("#", 1)[1], user_id)
            n += 1
        return n

    def update_role(self, user_id: str, role: str) -> None:
        for key, _ in self.store.list(BY_USER, prefix=f"{user_id}#"):
            h = key.split("#", 1)[1]
            if self.store.get(SESSIONS, h):
                self.store.update(SESSIONS, h, {"role": role})
