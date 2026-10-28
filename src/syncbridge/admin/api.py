"""Admin console backend: SAML login, OAuth connections, settings, monitoring, dead letters.

Roles come from Okta groups pushed over SCIM:
    viewer    see sync health, activity, connections and settings
    operator  + replay dead letters, run a reconciliation now
    admin     + connect/disconnect Salesforce and Slack, change settings, discard dead letters,
              read the audit log and the provisioned user list
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from html import escape
from urllib.parse import urlparse

from ..errors import PermanentError
from ..http import HttpError, Request, Response, Router, html_response, json_response, redirect
from ..oauth import pkce_pair
from ..platform import Platform
from ..saml.sp import SamlError, ServiceProvider
from ..scim.server import Directory
from ..sync.engine import ACTIVITY, METRICS, SETTINGS
from ..sync.worker import DEADLETTERS, replay
from .audit import AuditLog
from .sessions import Session, Sessions

CHANNEL_RE = re.compile(r"^[CG][A-Z0-9]{6,20}$")
PROVIDERS = ("salesforce", "slack")


@dataclass
class AdminContext:
    platform: Platform
    sessions: Sessions
    audit: AuditLog
    directory: Directory
    sp: ServiceProvider


def build_admin(p: Platform) -> AdminContext:
    sessions = Sessions(p.store, p.clock, p.settings)
    audit = AuditLog(p.store, p.clock)
    return AdminContext(
        p,
        sessions,
        audit,
        Directory(p.store, p.clock, p.settings, sessions, audit),
        ServiceProvider(p.settings, p.store, p.clock),
    )


def _safe_next(path: str | None) -> str:
    """Only same-site relative paths, so RelayState can't be used as an open redirect."""
    if not path or not path.startswith("/") or path.startswith("//") or "\\" in path:
        return "/"
    return path[:300]


def _error_page(title: str, message: str, status: int) -> Response:
    return html_response(
        f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,"
        f"initial-scale=1'><title>{escape(title)}</title><body style='font:15px system-ui;"
        f"max-width:520px;margin:15vh auto;padding:0 16px'><h1 style='font-size:20px'>"
        f"{escape(title)}</h1><p>{escape(message)}</p><p><a href='/saml/login'>Try again</a></p>",
        status,
    )


def admin_routes(ctx: AdminContext) -> Router:
    p, r = ctx.platform, Router()

    def session_of(req: Request) -> Session | None:
        return ctx.sessions.get(req.cookies.get(ctx.sessions.cookie_name))

    def require(role: str):
        def deco(fn):
            def wrapper(req: Request) -> Response:
                sess = session_of(req)
                if sess is None:
                    raise HttpError(401, "sign in required")
                if req.method not in ("GET", "HEAD"):
                    origin = req.header("origin")
                    if origin and urlparse(origin).netloc != urlparse(p.settings.base_url).netloc:
                        raise HttpError(403, "cross-origin request refused")
                    if not ctx.sessions.check_csrf(sess, req.header("x-csrf-token")):
                        raise HttpError(403, "missing or invalid CSRF token")
                if not sess.can(role):
                    raise HttpError(403, f"requires the {role} role")
                req.context["session"] = sess
                return fn(req)

            return wrapper

        return deco

    def actor(req: Request) -> str:
        return req.context["session"].email

    # --- SAML ------------------------------------------------------------------------------------

    @r.route("GET", "/saml/login")
    def saml_login(req: Request) -> Response:
        try:
            return redirect(ctx.sp.login_redirect(_safe_next(req.arg("next"))))
        except SamlError as exc:
            return _error_page("Single sign-on is not configured", str(exc), 503)

    @r.route("GET", "/saml/metadata")
    def saml_metadata(req: Request) -> Response:
        return Response(
            200, ctx.sp.metadata().encode(), {"Content-Type": "application/samlmetadata+xml"}
        )

    @r.route("POST", "/saml/acs")
    def saml_acs(req: Request) -> Response:
        form = req.form()
        try:
            ident = ctx.sp.consume(form.get("SAMLResponse", ""))
        except SamlError as exc:
            ctx.audit.record(
                "unknown", "auth.login_failed", "", {"reason": str(exc)[:200]}, req.source_ip
            )
            return _error_page(
                "Sign-in failed",
                "Your identity provider's response could not "
                "be verified. Contact your administrator.",
                403,
            )
        email = ident.first("email") or ident.name_id
        user = ctx.directory.find_by_username(ident.name_id) or ctx.directory.find_by_username(
            email
        )
        if user is None:
            if p.settings.require_scim_provisioning:
                ctx.audit.record(
                    email, "auth.login_denied", email, {"reason": "not provisioned"}, req.source_ip
                )
                return _error_page(
                    "No access",
                    "Your account has not been provisioned for "
                    "this app. Ask your Okta administrator to assign it to you.",
                    403,
                )
            role = "viewer"
            for g in ident.groups:
                mapped = p.settings.role_groups.get(g)
                if mapped == "admin" or (mapped == "operator" and role == "viewer"):
                    role = mapped
            user_id, name = f"saml:{email.lower()}", ident.first("firstName") or email
        else:
            if not user.get("active", True):
                ctx.audit.record(
                    email, "auth.login_denied", email, {"reason": "deactivated"}, req.source_ip
                )
                return _error_page("Account deactivated", "Your account is deactivated.", 403)
            role = ctx.directory.role_for(user)
            user_id, name = user["id"], user.get("displayName") or email
        raw, sess = ctx.sessions.create(user_id, email, name, role, ident.session_not_on_or_after)
        ctx.audit.record(email, "auth.login", email, {"role": role}, req.source_ip)
        return redirect(_safe_next(form.get("RelayState")), 303, cookies=[ctx.sessions.cookie(raw)])

    @r.route("POST", "/api/logout")
    @require("viewer")
    def logout(req: Request) -> Response:
        sess = req.context["session"]
        ctx.sessions.destroy_hash(sess.id_hash, sess.user_id)
        ctx.audit.record(sess.email, "auth.logout", sess.email, ip=req.source_ip)
        resp = json_response({"ok": True})
        resp.cookies.append(ctx.sessions.clear_cookie())
        return resp

    @r.route("GET", "/api/me")
    def me(req: Request) -> Response:
        sess = session_of(req)
        if sess is None:
            return json_response({"authenticated": False, "login_url": "/saml/login"}, 401)
        return json_response(
            {
                "authenticated": True,
                "email": sess.email,
                "name": sess.name,
                "role": sess.role,
                "csrf": sess.csrf,
                "expires": sess.expires,
                "environment": p.settings.environment,
            }
        )

    # --- monitoring ---------------------------------------------------------------------------------

    @r.route("GET", "/api/overview")
    @require("viewer")
    def overview(req: Request) -> Response:
        now = p.clock.now()
        hours = [
            time.strftime("%Y-%m-%dT%H", time.gmtime(now - 3600 * i)) for i in range(23, -1, -1)
        ]
        series, totals = [], {}
        for h in hours:
            item = p.store.get(METRICS, h) or {}
            series.append(
                {
                    "hour": h,
                    "events": item.get("events_processed", 0),
                    "dead_lettered": item.get("dead_lettered", 0),
                }
            )
            for k, v in item.items():
                totals[k] = totals.get(k, 0) + v
        lags = [a.get("lag_ms", 0) for _, a in p.store.list(ACTIVITY, limit=500, reverse=True)]
        lags.sort()
        depth = p.queue.depth() if hasattr(p.queue, "depth") else None
        recon = p.store.get(SETTINGS, "reconcile") or {}
        return json_response(
            {
                "connections": {k: p.vault.status(k) for k in PROVIDERS},
                "totals_24h": totals,
                "series": series,
                "dead_letters": len(p.store.list(DEADLETTERS, limit=1000)),
                "queue_depth": depth,
                "lag_ms_p50": lags[len(lags) // 2] if lags else None,
                "lag_ms_p95": lags[int(len(lags) * 0.95)] if lags else None,
                "reconcile": recon,
                "breakers": {"salesforce": p.sf.breaker.state, "slack": p.slack.breaker.state},
                "settings": p.store.get(SETTINGS, "sync") or {},
            }
        )

    @r.route("GET", "/api/activity")
    @require("viewer")
    def activity(req: Request) -> Response:
        limit = min(200, int(req.arg("limit", "50") or 50))
        return json_response([a for _, a in p.store.list(ACTIVITY, limit=limit, reverse=True)])

    @r.route("GET", "/api/deadletters")
    @require("viewer")
    def deadletters(req: Request) -> Response:
        return json_response(
            [
                {"id": k, **{x: v[x] for x in ("reason", "summary", "receive_count", "created_at")}}
                for k, v in p.store.list(DEADLETTERS, limit=500, reverse=True)
            ]
        )

    @r.route("POST", "/api/deadletters/{id}/replay")
    @require("operator")
    def replay_one(req: Request) -> Response:
        try:
            item = replay(p.store, p.queue, req.params["id"])
        except KeyError:
            raise HttpError(404, "dead letter not found") from None
        ctx.audit.record(actor(req), "deadletter.replay", item.get("summary", ""), ip=req.source_ip)
        return json_response({"ok": True})

    @r.route("POST", "/api/deadletters/replay-all")
    @require("operator")
    def replay_all(req: Request) -> Response:
        n = 0
        for key, _ in p.store.list(DEADLETTERS, limit=1000):
            replay(p.store, p.queue, key)
            n += 1
        ctx.audit.record(actor(req), "deadletter.replay_all", "", {"count": n}, req.source_ip)
        return json_response({"replayed": n})

    @r.route("DELETE", "/api/deadletters/{id}")
    @require("admin")
    def discard(req: Request) -> Response:
        item = p.store.get(DEADLETTERS, req.params["id"])
        if item is None:
            raise HttpError(404, "dead letter not found")
        p.store.delete(DEADLETTERS, req.params["id"])
        ctx.audit.record(
            actor(req),
            "deadletter.discard",
            item.get("summary", ""),
            {"reason": item.get("reason", "")[:200]},
            req.source_ip,
        )
        return json_response({"ok": True})

    @r.route("POST", "/api/reconcile")
    @require("operator")
    def reconcile(req: Request) -> Response:
        try:
            result = p.reconciler.run()
        except PermanentError as exc:
            raise HttpError(409, str(exc)) from exc
        ctx.audit.record(actor(req), "sync.reconcile", "", result, req.source_ip)
        return json_response(result)

    # --- connections -----------------------------------------------------------------------------------

    @r.route("GET", "/api/connections")
    @require("viewer")
    def connections(req: Request) -> Response:
        return json_response({k: p.vault.status(k) for k in PROVIDERS})

    @r.route("POST", "/api/connections/{provider}/start")
    @require("admin")
    def connect_start(req: Request) -> Response:
        provider = req.params["provider"]
        if provider == "salesforce":
            verifier, challenge = pkce_pair()
            state = p.states.issue(provider, actor(req), {"verifier": verifier})
            return json_response({"url": p.sf_auth.authorize_url(state, challenge)})
        if provider == "slack":
            state = p.states.issue(provider, actor(req))
            return json_response({"url": p.slack_auth.authorize_url(state)})
        raise HttpError(404, "unknown provider")

    @r.route("GET", "/oauth/{provider}/callback")
    def connect_callback(req: Request) -> Response:
        provider = req.params["provider"]
        sess = session_of(req)
        if sess is None or not sess.can("admin"):
            return _error_page("Not allowed", "Sign in as an admin to connect apps.", 403)
        if req.arg("error"):
            ctx.audit.record(
                sess.email,
                f"connection.{provider}.denied",
                "",
                {"error": req.arg("error")},
                req.source_ip,
            )
            return redirect("/#/connections?error=denied")
        try:
            state = p.states.consume(req.arg("state") or "", provider)
            if state["user"] != sess.email:
                raise PermanentError("OAuth state belongs to another user")
            if provider == "salesforce":
                tokens = p.sf_auth.exchange_code(req.arg("code") or "", state["verifier"])
            elif provider == "slack":
                tokens = p.slack_auth.exchange_code(req.arg("code") or "")
            else:
                raise PermanentError("unknown provider")
        except PermanentError as exc:
            ctx.audit.record(
                sess.email, f"connection.{provider}.failed", "", {"error": str(exc)}, req.source_ip
            )
            return _error_page("Connection failed", str(exc), 400)
        p.vault.save(provider, tokens, sess.email)
        if provider == "salesforce":
            cfg = p.store.get(SETTINGS, "sync") or {}
            p.store.put(SETTINGS, "sync", {**cfg, "instance_url": tokens["instance_url"]})
        ctx.audit.record(
            sess.email,
            f"connection.{provider}.connected",
            tokens.get("instance_url") or tokens.get("team_name", ""),
            ip=req.source_ip,
        )
        return redirect(f"/#/connections?connected={provider}")

    @r.route("DELETE", "/api/connections/{provider}")
    @require("admin")
    def disconnect(req: Request) -> Response:
        provider = req.params["provider"]
        if provider not in PROVIDERS:
            raise HttpError(404, "unknown provider")
        try:
            tokens = p.vault.load(provider)
        except PermanentError:
            raise HttpError(404, "not connected") from None
        (p.sf_auth if provider == "salesforce" else p.slack_auth).revoke(
            tokens.get("refresh_token") or tokens["access_token"]
        )
        p.vault.delete(provider)
        ctx.audit.record(actor(req), f"connection.{provider}.disconnected", ip=req.source_ip)
        return json_response({"ok": True})

    # --- settings, audit, users ---------------------------------------------------------------------------

    @r.route("GET", "/api/settings")
    @require("viewer")
    def get_settings(req: Request) -> Response:
        return json_response(p.store.get(SETTINGS, "sync") or {})

    @r.route("PUT", "/api/settings")
    @require("admin")
    def put_settings(req: Request) -> Response:
        body = req.json() or {}
        channel = str(body.get("channel_id", "")).strip()
        if not CHANNEL_RE.match(channel):
            raise HttpError(400, "channel_id must be a Slack channel ID like C0123456789")
        cfg = p.store.get(SETTINGS, "sync") or {}
        p.store.put(SETTINGS, "sync", {**cfg, "channel_id": channel})
        ctx.audit.record(
            actor(req),
            "settings.update",
            "channel_id",
            {"from": cfg.get("channel_id"), "to": channel},
            req.source_ip,
        )
        return json_response({**cfg, "channel_id": channel})

    @r.route("GET", "/api/audit")
    @require("admin")
    def audit_log(req: Request) -> Response:
        return json_response(ctx.audit.recent(min(500, int(req.arg("limit", "100") or 100))))

    @r.route("GET", "/api/users")
    @require("admin")
    def users(req: Request) -> Response:
        out = []
        for u in ctx.directory.list_users(None):
            out.append(
                {
                    "id": u["id"],
                    "userName": u["userName"],
                    "name": u.get("displayName"),
                    "active": u.get("active", True),
                    "groups": [g["display"] for g in u.get("groups", [])],
                    "role": ctx.directory.role_for(u),
                    "created": u["meta"]["created"],
                }
            )
        return json_response(out)

    return r
