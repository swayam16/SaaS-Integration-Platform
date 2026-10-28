"""A Slack workspace simulator: the Web API methods the integration calls, plus people who reply
in threads, edit their replies and click buttons. Their activity goes out as Events API and
interactivity payloads with real v0 signatures, including Slack's own retry behaviour."""

from __future__ import annotations

import json
import random
import threading
import uuid
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from ..clock import Clock
from .faults import DeliveryPlan, FaultPlan

USERS = {
    f"U0{n:07d}": {"name": name, "email": f"{name.split()[0].lower()}@acme.example"}
    for n, name in enumerate(
        [
            "Avery Chen",
            "Jordan Patel",
            "Sam Rivera",
            "Riley Okafor",
            "Morgan Silva",
            "Casey Novak",
            "Quinn Larsen",
            "Drew Haddad",
        ]
    )
}


@dataclass
class OutboundEvent:
    deliver_at: float
    kind: str  # "event" | "interaction"
    body: dict
    retry_num: int = 0


@dataclass
class SlackSim:
    clock: Clock
    signing_secret: str = "slack-signing-secret"
    team_id: str = "T0SIM0001"
    bot_user_id: str = "U0BOT0001"
    bot_id: str = "B0BOT0001"
    faults: FaultPlan = field(default_factory=FaultPlan)
    delivery: DeliveryPlan = field(default_factory=DeliveryPlan)
    rng: random.Random = field(default_factory=lambda: random.Random(4))

    def __post_init__(self) -> None:
        self.channels: dict[str, list[dict]] = {"C0SUPPORT1": []}
        self.by_ts: dict[tuple[str, str], dict] = {}
        self.tokens: set[str] = set()
        self.codes: set[str] = set()
        self._last_ts = 0
        self.outbox: list[OutboundEvent] = []
        self.api_calls = Counter()
        self.posts_by_sync_key = Counter()
        self.updates_applied = 0
        self._lock = threading.RLock()

    # --- helpers ----------------------------------------------------------------------------------

    def _ts(self) -> str:
        micros = max(int(self.clock.now() * 1_000_000), self._last_ts + 1)
        self._last_ts = micros
        return f"{micros // 1_000_000}.{micros % 1_000_000:06d}"

    def _add(self, channel: str, msg: dict) -> dict:
        self.channels.setdefault(channel, []).append(msg)
        self.by_ts[(channel, msg["ts"])] = msg
        if msg.get("thread_ts") and msg["thread_ts"] != msg["ts"]:
            parent = self.by_ts.get((channel, msg["thread_ts"]))
            if parent is not None:
                parent.setdefault("replies", []).append(msg["ts"])
        return msg

    # --- people ------------------------------------------------------------------------------------

    def human_reply(self, channel: str, thread_ts: str, user: str, text: str) -> dict:
        msg = self._add(
            channel,
            {
                "type": "message",
                "user": user,
                "text": text,
                "ts": self._ts(),
                "thread_ts": thread_ts,
            },
        )
        self._emit_event(
            {
                "type": "message",
                "channel": channel,
                "user": user,
                "text": text,
                "ts": msg["ts"],
                "thread_ts": thread_ts,
                "event_ts": msg["ts"],
                "channel_type": "channel",
            }
        )
        return msg

    def human_edit(self, channel: str, ts: str, text: str) -> None:
        msg = self.by_ts[(channel, ts)]
        msg["text"] = text
        edited = self._ts()
        msg["edited"] = {"user": msg["user"], "ts": edited}
        self._emit_event(
            {
                "type": "message",
                "subtype": "message_changed",
                "channel": channel,
                "hidden": True,
                "ts": edited,
                "event_ts": edited,
                "message": {
                    "type": "message",
                    "user": msg["user"],
                    "text": text,
                    "ts": ts,
                    "thread_ts": msg.get("thread_ts"),
                    "edited": msg["edited"],
                },
            }
        )

    def click(self, channel: str, message_ts: str, action_id: str, value: str, user: str) -> None:
        payload = {
            "type": "block_actions",
            "team": {"id": self.team_id, "domain": "acme"},
            "user": {
                "id": user,
                "username": USERS.get(user, {}).get("name", user),
                "team_id": self.team_id,
            },
            "api_app_id": "A0SYNCBRDG",
            "token": "deprecated-verification-token",
            "container": {
                "type": "message",
                "message_ts": message_ts,
                "channel_id": channel,
                "is_ephemeral": False,
            },
            "trigger_id": f"{uuid.uuid4().int % 10**12}.{uuid.uuid4().hex[:10]}",
            "channel": {"id": channel, "name": "support-cases"},
            "response_url": "https://hooks.slack.com/actions/T0SIM0001/1/xyz",
            "actions": [
                {
                    "action_id": action_id,
                    "block_id": f"case_actions:{value}",
                    "value": value,
                    "type": "button",
                    "action_ts": self._ts(),
                }
            ],
        }
        self._schedule(OutboundEvent(self.clock.now() + 0.05, "interaction", payload))

    def bot_post(self, channel: str, text: str, thread_ts: str | None = None) -> dict:
        """A post by another app (must be ignored by the integration)."""
        msg = self._add(
            channel,
            {
                "type": "message",
                "bot_id": "B0OTHER01",
                "text": text,
                "ts": self._ts(),
                "thread_ts": thread_ts,
            },
        )
        self._emit_event(
            {
                "type": "message",
                "subtype": "bot_message",
                "bot_id": "B0OTHER01",
                "channel": channel,
                "text": text,
                "ts": msg["ts"],
                "thread_ts": thread_ts,
            }
        )
        return msg

    def _emit_event(self, event: dict) -> None:
        body = {
            "token": "deprecated",
            "team_id": self.team_id,
            "api_app_id": "A0SYNCBRDG",
            "event": event,
            "type": "event_callback",
            "event_id": "Ev" + uuid.uuid4().hex[:10].upper(),
            "event_time": int(self.clock.now()),
            "authorizations": [
                {"team_id": self.team_id, "user_id": self.bot_user_id, "is_bot": True}
            ],
        }
        self._schedule(OutboundEvent(self.clock.now() + 0.05, "event", body))

    def _schedule(self, out: OutboundEvent) -> None:
        d = self.delivery
        if d.max_delay:
            out.deliver_at += d.rng.uniform(0, d.max_delay)
        self.outbox.append(out)
        if d.rng.random() < d.duplicate:
            # Slack did not get our 200 within 3 s (cold start, slow network) and retries.
            d.injected["duplicated"] += 1
            self.outbox.append(
                OutboundEvent(
                    out.deliver_at + d.rng.choice([1, 60, 300]), out.kind, out.body, retry_num=1
                )
            )

    def due_events(self) -> list[OutboundEvent]:
        now = self.clock.now()
        due = [o for o in self.outbox if o.deliver_at <= now]
        if due:
            self.outbox = [o for o in self.outbox if o.deliver_at > now]
        return due

    def encode(self, out: OutboundEvent) -> tuple[bytes, dict[str, str]]:
        from ..slack.webhook import sign

        if out.kind == "event":
            body = json.dumps(out.body).encode()
            ctype = "application/json"
        else:
            body = urlencode({"payload": json.dumps(out.body)}).encode()
            ctype = "application/x-www-form-urlencoded"
        ts = int(self.clock.now())
        headers = {
            "content-type": ctype,
            "x-slack-request-timestamp": str(ts),
            "x-slack-signature": sign(self.signing_secret, ts, body),
        }
        if out.retry_num:
            headers["x-slack-retry-num"] = str(out.retry_num)
            headers["x-slack-retry-reason"] = "http_timeout"
        return body, headers

    # --- Web API -------------------------------------------------------------------------------------

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            return self._handle(request)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        self.api_calls[method] += 1
        if method == "oauth.v2.access":
            return self._oauth(request)
        if method.startswith("oauth.v2.authorize"):
            return self._authorize(request)
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        if token not in self.tokens:
            return httpx.Response(200, json={"ok": False, "error": "invalid_auth"})
        write = method in ("chat.postMessage", "chat.update")
        fault = self.faults.pick(self.clock.now(), write)
        if fault in ("outage", "error_before"):
            return httpx.Response(503, text="upstream connect error")
        if fault == "connect_error":
            raise httpx.ConnectError("connection reset", request=request)
        if fault == "rate_limit":
            return httpx.Response(
                429,
                headers={"Retry-After": str(self.rng.choice([1, 2, 3, 30]))},
                json={"ok": False, "error": "ratelimited"},
            )
        if request.method == "POST" and request.headers.get("content-type", "").startswith(
            "application/json"
        ):
            args = json.loads(request.content or b"{}")
        else:
            args = {k: v[0] for k, v in parse_qs(urlparse(str(request.url)).query).items()}
            if request.content:
                args.update({k: v[0] for k, v in parse_qs(request.content.decode()).items()})
        handler = getattr(self, "_m_" + method.replace(".", "_"), None)
        if handler is None:
            return httpx.Response(200, json={"ok": False, "error": "unknown_method"})
        resp = handler(args)
        if fault == "error_after":
            return httpx.Response(500, text="internal error")
        if fault == "timeout_after":
            raise httpx.ReadTimeout("read timed out", request=request)
        return resp

    def _oauth(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        if form.get("code") in self.codes or form.get("grant_type") == "refresh_token":
            self.codes.discard(form.get("code", ""))
            token = "xoxb-sim-" + uuid.uuid4().hex
            self.tokens.add(token)
            return httpx.Response(
                200,
                json={
                    "ok": True,
                    "access_token": token,
                    "token_type": "bot",
                    "scope": "chat:write,channels:history,groups:history,users:read",
                    "bot_user_id": self.bot_user_id,
                    "app_id": "A0SYNCBRDG",
                    "team": {"id": self.team_id, "name": "Acme Support"},
                },
            )
        return httpx.Response(200, json={"ok": False, "error": "invalid_code"})

    def _authorize(self, request: httpx.Request) -> httpx.Response:
        q = parse_qs(urlparse(str(request.url)).query)
        code = uuid.uuid4().hex
        self.codes.add(code)
        return httpx.Response(
            302,
            headers={
                "Location": f"{q['redirect_uri'][0]}?code={code}&state={q.get('state', [''])[0]}"
            },
        )

    def issue_token(self) -> str:
        token = "xoxb-sim-" + uuid.uuid4().hex
        self.tokens.add(token)
        return token

    def _m_auth_test(self, args: dict) -> httpx.Response:
        return httpx.Response(
            200, json={"ok": True, "team_id": self.team_id, "user_id": self.bot_user_id}
        )

    def _m_auth_revoke(self, args: dict) -> httpx.Response:
        self.tokens.clear()
        return httpx.Response(200, json={"ok": True, "revoked": True})

    def _m_chat_postMessage(self, args: dict) -> httpx.Response:
        channel = args.get("channel")
        if channel not in self.channels:
            return httpx.Response(200, json={"ok": False, "error": "channel_not_found"})
        thread_ts = args.get("thread_ts")
        if thread_ts and (channel, thread_ts) not in self.by_ts:
            return httpx.Response(200, json={"ok": False, "error": "thread_not_found"})
        msg = self._add(
            channel,
            {
                "type": "message",
                "bot_id": self.bot_id,
                "user": self.bot_user_id,
                "text": args.get("text", ""),
                "blocks": args.get("blocks", []),
                "ts": self._ts(),
                "thread_ts": thread_ts,
                "metadata": args.get("metadata"),
            },
        )
        key = ((args.get("metadata") or {}).get("event_payload") or {}).get("sync_key")
        if key:
            self.posts_by_sync_key[key] += 1
        return httpx.Response(
            200,
            json={
                "ok": True,
                "channel": channel,
                "ts": msg["ts"],
                "message": {k: v for k, v in msg.items() if k != "replies"},
            },
        )

    def _m_chat_update(self, args: dict) -> httpx.Response:
        msg = self.by_ts.get((args.get("channel"), args.get("ts")))
        if msg is None:
            return httpx.Response(200, json={"ok": False, "error": "message_not_found"})
        msg.update(
            {
                "text": args.get("text", msg["text"]),
                "blocks": args.get("blocks", []),
                "edited": {"user": self.bot_user_id, "ts": self._ts()},
            }
        )
        if args.get("metadata"):
            msg["metadata"] = args["metadata"]
        self.updates_applied += 1
        return httpx.Response(
            200,
            json={"ok": True, "channel": args["channel"], "ts": args["ts"], "text": msg["text"]},
        )

    def _history(self, messages: list[dict], args: dict) -> httpx.Response:
        oldest = float(args.get("oldest") or 0)
        limit = min(int(args.get("limit") or 100), 1000)
        offset = int(args.get("cursor") or 0)
        include_meta = str(args.get("include_all_metadata", "")).lower() == "true"
        rows = [m for m in messages if float(m["ts"]) > oldest]
        if args.get("latest"):
            latest = float(args["latest"])
            inclusive = str(args.get("inclusive", "")).lower() == "true"
            rows = [
                m
                for m in rows
                if float(m["ts"]) < latest or (inclusive and float(m["ts"]) == latest)
            ]
        page = rows[offset : offset + limit]
        out = []
        for m in page:
            item = {k: v for k, v in m.items() if k not in ("replies",)}
            if not include_meta:
                item.pop("metadata", None)
            out.append(item)
        more = offset + limit < len(rows)
        return httpx.Response(
            200,
            json={
                "ok": True,
                "messages": out,
                "has_more": more,
                "response_metadata": {"next_cursor": str(offset + limit) if more else ""},
            },
        )

    def _m_conversations_history(self, args: dict) -> httpx.Response:
        channel = args.get("channel")
        if channel not in self.channels:
            return httpx.Response(200, json={"ok": False, "error": "channel_not_found"})
        top = [
            m
            for m in reversed(self.channels[channel])
            if not m.get("thread_ts") or m.get("thread_ts") == m["ts"]
        ]
        return self._history(top, args)

    def _m_conversations_replies(self, args: dict) -> httpx.Response:
        channel, ts = args.get("channel"), args.get("ts")
        parent = self.by_ts.get((channel, ts))
        if parent is None:
            return httpx.Response(200, json={"ok": False, "error": "thread_not_found"})
        thread = [parent] + [self.by_ts[(channel, r)] for r in parent.get("replies", [])]
        return self._history(thread, args)

    def _m_users_info(self, args: dict) -> httpx.Response:
        user = USERS.get(args.get("user", ""))
        if user is None:
            return httpx.Response(200, json={"ok": False, "error": "user_not_found"})
        return httpx.Response(
            200,
            json={
                "ok": True,
                "user": {
                    "id": args["user"],
                    "name": user["name"].split()[0].lower(),
                    "profile": {
                        "real_name": user["name"],
                        "display_name": user["name"].split()[0],
                        "email": user["email"],
                    },
                },
            },
        )

    # --- inspection for the harness --------------------------------------------------------------

    def top_level(self, channel: str = "C0SUPPORT1") -> list[dict]:
        return [
            m for m in self.channels[channel] if not m.get("thread_ts") or m["thread_ts"] == m["ts"]
        ]
