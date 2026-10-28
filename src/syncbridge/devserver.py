"""Local stack: `syncbridge dev` (or `make dev`).

One process serves everything on http://localhost:8080:

    /                       admin console (console/dist)
    /api, /saml, /oauth     console backend          (same code as the api Lambda)
    /webhooks               webhook receivers         (same code as the webhooks Lambda)
    /scim/v2                SCIM server               (same code as the scim Lambda)
    /_idp                   mock Okta (SAML IdP)
    /_sim/salesforce/ui     simulated Salesforce org: edit cases, add case messages
    /_sim/slack/ui          simulated Slack channel: see synced messages, reply, click buttons

Background threads play the queue worker and the webhook delivery from the simulators. Demo
users are provisioned through the SCIM endpoint at start-up, as Okta would.
"""

from __future__ import annotations

import base64
import json
import random
import secrets
import threading
import time
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from .admin.api import admin_routes, build_admin
from .clock import Clock
from .config import Settings
from .crypto import sha256_hex
from .http import Request, Response, html_response, parse_cookie_header, redirect
from .platform import build_platform
from .salesforce.webhook import sign as sf_sign
from .saml.mock_idp import MockIdP
from .scim.server import scim_routes
from .sim.harness import ACCOUNTS, AGENTS, SUBJECTS
from .sim.salesforce import SalesforceSim
from .sim.slack import USERS, SlackSim
from .sync.engine import SETTINGS
from .webhooks import webhook_routes

CHANNEL = "C0SUPPORT1"
DEMO_USERS = [
    ("avery@acme.example", "Avery", "Chen", ["SyncBridge Admins"], True),
    ("jordan@acme.example", "Jordan", "Patel", ["SyncBridge Operators"], True),
    ("sam@acme.example", "Sam", "Rivera", ["SyncBridge Viewers"], True),
    ("riley@acme.example", "Riley", "Okafor", ["SyncBridge Operators"], False),
]
CONSOLE_DIST = Path(__file__).resolve().parents[2] / "console" / "dist"


def _to_httpx(req: Request, url: str) -> httpx.Request:
    return httpx.Request(req.method, url, headers=req.headers, content=req.body)


def _from_httpx(resp: httpx.Response) -> Response:
    names = {"location": "Location", "content-type": "Content-Type", "retry-after": "Retry-After"}
    headers = {names[k.lower()]: v for k, v in resp.headers.items() if k.lower() in names}
    return Response(resp.status_code, resp.content, headers)


class DevStack:
    def __init__(self, port: int = 8080, demo: bool = True):
        self.base = f"http://localhost:{port}"
        self.clock = Clock()
        self.sf = SalesforceSim(self.clock, webhook_secret=secrets.token_hex(16))
        self.slack = SlackSim(self.clock, signing_secret=secrets.token_hex(16))
        self.idp = MockIdP("http://www.okta.com/exkDEV0mock", f"{self.base}/_idp/sso", self.clock)
        self.scim_token = secrets.token_urlsafe(24)
        self.settings = Settings(
            base_url=self.base,
            environment="local",
            sf_login_url=f"{self.base}/_sim/salesforce",
            sf_client_id=self.sf.client_id,
            sf_client_secret=self.sf.client_secret,
            sf_webhook_secret=self.sf.webhook_secret,
            slack_api_base=f"{self.base}/_sim/slack/api",
            slack_oauth_base=f"{self.base}/_sim/slack/oauth.v2.authorize",
            slack_client_id="dev-slack",
            slack_client_secret="dev-slack-secret",
            slack_signing_secret=self.slack.signing_secret,
            saml_idp_entity_id=self.idp.entity_id,
            saml_idp_sso_url=self.idp.sso_url,
            saml_idp_cert=self.idp.cert_pem,
            scim_token_sha256=sha256_hex(self.scim_token),
            local_encryption_key=base64.b64encode(secrets.token_bytes(32)).decode(),
        )
        self.platform = build_platform(
            self.settings, clock=self.clock, transport=httpx.MockTransport(self._outbound)
        )
        self.admin = build_admin(self.platform)
        self.routers = [
            webhook_routes(self.platform),
            admin_routes(self.admin),
            scim_routes(self.admin.directory, self.settings),
        ]
        self.rng = random.Random()
        self.stop = threading.Event()
        self._provision()
        if demo:
            self._connect_and_seed()

    # --- outbound HTTP from the platform goes to the simulators ----------------------------------

    def _outbound(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/_sim/salesforce") or request.url.host.endswith("salesforce.com"):
            url = str(request.url).replace(
                f"{self.base}/_sim/salesforce", "https://login.salesforce.com"
            )
            return self.sf(
                httpx.Request(request.method, url, headers=request.headers, content=request.content)
            )
        if path.startswith("/_sim/slack") or request.url.host == "slack.com":
            return self.slack(request)
        return httpx.Response(502, text="no route in dev stack")

    # --- start-up ----------------------------------------------------------------------------------

    def _scim(self, method: str, path: str, body: dict) -> dict:
        req = Request(
            method,
            path,
            headers={"authorization": f"Bearer {self.scim_token}"},
            body=json.dumps(body).encode(),
        )
        resp = self.routers[2].dispatch(req)
        return json.loads(resp.body or b"{}")

    def _provision(self) -> None:
        groups: dict[str, list[str]] = {}
        for email, first, last, gs, active in DEMO_USERS:
            user = self._scim(
                "POST",
                "/scim/v2/Users",
                {
                    "userName": email,
                    "name": {"givenName": first, "familyName": last},
                    "emails": [{"value": email, "type": "work", "primary": True}],
                    "active": active,
                },
            )
            for g in gs:
                groups.setdefault(g, []).append(user["id"])
        for name, members in groups.items():
            self._scim(
                "POST",
                "/scim/v2/Groups",
                {"displayName": name, "members": [{"value": m} for m in members]},
            )

    def _connect_and_seed(self) -> None:
        p = self.platform
        self.sf.codes["boot"] = ""
        tokens = self.sf(
            httpx.Request(
                "POST",
                "https://login.salesforce.com/services/oauth2/token",
                content=b"grant_type=authorization_code&code=boot",
            )
        ).json()
        p.vault.save(
            "salesforce",
            {
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "instance_url": tokens["instance_url"],
            },
            "avery@acme.example",
        )
        p.vault.save(
            "slack",
            {
                "access_token": self.slack.issue_token(),
                "team_id": self.slack.team_id,
                "team_name": "Acme Support",
            },
            "avery@acme.example",
        )
        p.store.put(SETTINGS, "sync", {"channel_id": CHANNEL, "instance_url": self.sf.instance_url})
        for _ in range(24):
            self._random_activity()

    # --- background loops -----------------------------------------------------------------------------

    def _deliver(self) -> None:
        for out in self.sf.due_notifications():
            body = json.dumps(out.payload).encode()
            ts = int(self.clock.now())
            self.dispatch(
                Request(
                    "POST",
                    "/webhooks/salesforce",
                    body=body,
                    headers={
                        "x-syncbridge-timestamp": str(ts),
                        "x-syncbridge-signature": sf_sign(self.sf.webhook_secret, ts, body),
                    },
                )
            )
        for out in self.slack.due_events():
            body, headers = self.slack.encode(out)
            path = (
                "/webhooks/slack/events" if out.kind == "event" else "/webhooks/slack/interactivity"
            )
            self.dispatch(Request("POST", path, body=body, headers=headers))

    def _work(self) -> None:
        q = self.platform.queue
        for m in q.receive(10):
            outcome = self.platform.worker.handle(m.body, m.receive_count)
            if outcome.ack:
                q.delete(m)
            elif outcome.delay is not None:
                q.change_visibility(m, min(outcome.delay, 10))

    def _random_activity(self) -> None:
        r = self.rng
        cases = list(self.sf.cases)
        roll = r.random()
        if roll < 0.45 or len(cases) < 5:
            self.sf.create_case(
                {
                    "Subject": r.choice(SUBJECTS),
                    "AccountName": r.choice(ACCOUNTS),
                    "OwnerName": r.choice(AGENTS),
                    "Priority": r.choice(["Low", "Medium", "High"]),
                    "Description": "Reported via web form.",
                }
            )
        elif roll < 0.7:
            self.sf.update_case(
                r.choice(cases[-30:]),
                {"Status": r.choice(["Working", "On Hold", "Escalated", "Closed"])},
            )
        elif roll < 0.85:
            self.sf.add_message(
                {
                    "Case__c": r.choice(cases[-30:]),
                    "Author__c": r.choice(AGENTS),
                    "Body__c": "We've reproduced it and are working on a fix.",
                }
            )
        else:
            top = [m for m in self.slack.top_level(CHANNEL) if m.get("metadata")][-30:]
            if top:
                self.slack.human_reply(
                    CHANNEL,
                    r.choice(top)["ts"],
                    r.choice(list(USERS)),
                    r.choice(
                        [
                            "Customer confirmed it's fixed.",
                            "Any update?",
                            "Escalating to their account team.",
                        ]
                    ),
                )

    def run_background(self, activity_every: float = 6.0) -> None:
        def loop():
            last = 0.0
            while not self.stop.is_set():
                try:
                    self._deliver()
                    self._work()
                    if activity_every and time.time() - last > activity_every:
                        self._random_activity()
                        last = time.time()
                except Exception as exc:  # noqa: BLE001 - keep the dev loop alive
                    print("background error:", exc)
                time.sleep(0.2)

        threading.Thread(target=loop, daemon=True).start()

    # --- HTTP -------------------------------------------------------------------------------------------

    def dispatch(self, req: Request) -> Response:
        path = req.path
        if path.startswith("/_idp"):
            return self._idp(req)
        if path.startswith("/_sim/salesforce/ui"):
            return self._sf_ui(req)
        if path.startswith("/_sim/slack/ui"):
            return self._slack_ui(req)
        if path.startswith("/_sim/salesforce/services/oauth2/authorize"):
            q = urlencode({k: v[0] for k, v in req.query.items()})
            return _from_httpx(
                self.sf(
                    httpx.Request(
                        "GET", f"https://login.salesforce.com/services/oauth2/authorize?{q}"
                    )
                )
            )
        if path.startswith("/_sim/slack/oauth.v2.authorize"):
            q = urlencode({k: v[0] for k, v in req.query.items()})
            return _from_httpx(
                self.slack(httpx.Request("GET", f"https://slack.com/api/oauth.v2.authorize?{q}"))
            )
        for r in self.routers:
            if r.handles(path):
                return r.dispatch(req)
        if path.startswith(("/webhooks", "/api", "/saml", "/oauth", "/scim")):
            return Response(404, b'{"error": "not found"}', {"Content-Type": "application/json"})
        return self._static(path)

    def _static(self, path: str) -> Response:
        if not CONSOLE_DIST.exists():
            return html_response(
                "<p>Console not built. Run <code>npm run build</code> in "
                "console/, or <code>npm run dev</code> for hot reload.</p>",
                503,
            )
        target = (CONSOLE_DIST / path.lstrip("/")).resolve()
        if not str(target).startswith(str(CONSOLE_DIST)) or not target.is_file():
            target = CONSOLE_DIST / "index.html"
        ctype = {
            ".js": "text/javascript",
            ".css": "text/css",
            ".svg": "image/svg+xml",
            ".html": "text/html; charset=utf-8",
            ".png": "image/png",
            ".ico": "image/x-icon",
        }.get(target.suffix, "application/octet-stream")
        return Response(
            200,
            target.read_bytes(),
            {
                "Content-Type": ctype,
                "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; frame-ancestors 'none'",
            },
        )

    def _idp(self, req: Request) -> Response:
        if req.path == "/_idp/metadata":
            return Response(200, self.idp.metadata().encode(), {"Content-Type": "application/xml"})
        users = []
        for u in self.admin.directory.list_users(None):
            if u.get("active", True):
                users.append(
                    {
                        "email": u["userName"],
                        "name": u.get("displayName", ""),
                        "groups": [g["display"] for g in u.get("groups", [])],
                    }
                )
        users.append({"email": "intruder@other.example", "name": "Not provisioned", "groups": []})
        if req.method == "GET":
            return html_response(
                self.idp.login_page(
                    urlencode({k: v[0] for k, v in req.query.items()}), users, self.settings.acs_url
                )
            )
        form = req.form()
        user = next((u for u in users if u["email"] == form.get("user")), None)
        if user is None:
            return html_response("unknown user", 400)
        first = user["name"].split()[0] if user["name"] else ""
        resp = self.idp.response(
            name_id=user["email"],
            acs_url=form.get("acs") or self.settings.acs_url,
            audience=form.get("audience") or self.settings.sp_entity_id,
            in_response_to=form.get("request_id") or None,
            attributes={"email": [user["email"]], "firstName": [first], "groups": user["groups"]},
        )
        return html_response(
            self.idp.post_form(
                form.get("acs") or self.settings.acs_url, resp, form.get("RelayState", "/")
            )
        )

    # --- simulator UIs (development only) --------------------------------------------------------------

    def _page(self, title: str, body: str) -> Response:
        return html_response(f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)}</title>
<style>body{{font:14px/1.45 system-ui;margin:0;background:#f6f6f8;color:#1d1c1d}}
header{{background:{"#032d60" if "Salesforce" in title else "#3f0e40"};color:#fff;padding:12px 18px;font-weight:600}}
main{{max-width:920px;margin:0 auto;padding:16px}}.card{{background:#fff;border:1px solid #e1e1e5;border-radius:8px;padding:12px 14px;margin:10px 0}}
.meta{{color:#616061;font-size:12px}}.reply{{margin:8px 0 0 18px;padding-left:10px;border-left:3px solid #e1e1e5}}
button,select,input{{font:inherit}}button{{border:1px solid #ccc;background:#fff;border-radius:6px;padding:3px 10px;cursor:pointer}}
button.primary{{background:#007a5a;color:#fff;border-color:#007a5a}}button.danger{{color:#e01e5a;border-color:#e01e5a}}
table{{width:100%;border-collapse:collapse;background:#fff}}td,th{{padding:7px 8px;border-bottom:1px solid #eee;text-align:left;font-size:13px}}
form.inline{{display:inline}}</style>
<script>setTimeout(()=>{{if(!document.activeElement||document.activeElement.tagName!=='INPUT')location.reload()}},5000)</script>
</head><body><header>{escape(title)}</header><main>{body}</main></body></html>""")

    def _slack_ui(self, req: Request) -> Response:
        if req.method == "POST":
            f = req.form()
            user = next(iter(USERS))
            if f.get("action_id"):
                self.slack.click(CHANNEL, f["ts"], f["action_id"], f["value"], user)
            elif f.get("text"):
                self.slack.human_reply(CHANNEL, f["ts"], user, f["text"][:500])
            return redirect("/_sim/slack/ui", 303)
        cards = []
        for m in reversed(self.slack.top_level(CHANNEL)[-40:]):
            buttons = ""
            for b in m.get("blocks", []):
                if b.get("type") == "actions":
                    for el in b["elements"]:
                        buttons += (
                            f'<form class="inline" method="post"><input type="hidden" name="ts" '
                            f'value="{m["ts"]}"><input type="hidden" name="action_id" '
                            f'value="{el["action_id"]}"><input type="hidden" name="value" '
                            f'value="{escape(el["value"])}"><button class="{el.get("style", "")}">'
                            f"{escape(el['text']['text'])}</button></form> "
                        )
            replies = "".join(
                f'<div class="reply"><b>{escape(USERS.get(r.get("user", ""), {}).get("name", "SyncBridge") if not r.get("bot_id") else "SyncBridge")}</b> '
                f"{escape(r.get('text', ''))}</div>"
                for r in (self.slack.by_ts[(CHANNEL, ts)] for ts in m.get("replies", []))
            )
            cards.append(
                f'<div class="card"><div class="meta">SyncBridge app · {time.strftime("%H:%M:%S", time.localtime(float(m["ts"])))}'
                f"{' · edited' if m.get('edited') else ''}</div><div>{escape(m.get('text', ''))}</div>"
                f'<div style="margin-top:6px">{buttons}</div>{replies}'
                f'<form method="post" style="margin-top:8px"><input type="hidden" name="ts" value="{m["ts"]}">'
                f'<input name="text" placeholder="Reply in thread…" style="width:70%"> <button>Send</button></form></div>'
            )
        return self._page(
            "Slack (simulated) · #support-cases", "".join(cards) or "<p>No messages yet.</p>"
        )

    def _sf_ui(self, req: Request) -> Response:
        if req.method == "POST":
            f = req.form()
            if f.get("status"):
                self.sf.update_case(f["id"], {"Status": f["status"]})
            elif f.get("body"):
                self.sf.add_message(
                    {"Case__c": f["id"], "Author__c": "Priya Raman", "Body__c": f["body"][:500]}
                )
            elif f.get("new"):
                self.sf.create_case(
                    {"Subject": f["new"][:120], "AccountName": "Globex", "OwnerName": "Priya Raman"}
                )
            return redirect("/_sim/salesforce/ui", 303)
        rows = []
        for c in list(self.sf.cases.values())[-40:][::-1]:
            opts = "".join(
                f"<option {'selected' if c['Status'] == s else ''}>{s}</option>"
                for s in ["New", "Working", "On Hold", "Escalated", "Closed"]
            )
            msgs = [m for m in self.sf.messages.values() if m.get("Case__c") == c["Id"]]
            rows.append(
                f"<tr><td>{c['CaseNumber']}</td><td>{escape(c['Subject'])}</td><td>{c['Priority']}</td>"
                f'<td><form class="inline" method="post"><input type="hidden" name="id" value="{c["Id"]}">'
                f'<select name="status" onchange="this.form.submit()">{opts}</select></form></td>'
                f"<td>{len(msgs)} ({sum(1 for m in msgs if m.get('Source__c') == 'Slack')} from Slack)</td>"
                f'<td><form class="inline" method="post"><input type="hidden" name="id" value="{c["Id"]}">'
                f'<input name="body" placeholder="Case message" size="18"> <button>Add</button></form></td></tr>'
            )
        body = (
            '<form method="post" class="card"><input name="new" placeholder="New case subject" size="40"> '
            "<button>Create case</button></form><table><tr><th>Case</th><th>Subject</th><th>Priority</th>"
            "<th>Status</th><th>Messages</th><th></th></tr>" + "".join(rows) + "</table>"
        )
        return self._page("Salesforce (simulated) · Cases", body)


def serve(port: int = 8080, demo: bool = True) -> None:
    stack = DevStack(port, demo)
    stack.run_background()

    class Handler(BaseHTTPRequestHandler):
        def _go(self) -> None:
            url = urlparse(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            headers = {k.lower(): v for k, v in self.headers.items()}
            req = Request(
                self.command,
                url.path,
                parse_qs(url.query, keep_blank_values=True),
                headers,
                self.rfile.read(length) if length else b"",
                parse_cookie_header(headers.get("cookie", "")),
                source_ip=self.client_address[0],
            )
            resp = stack.dispatch(req)
            self.send_response(resp.status)
            for k, v in {**resp.headers}.items():
                self.send_header(k, v)
            for c in resp.cookies:
                self.send_header("Set-Cookie", c)
            self.send_header("Content-Length", str(len(resp.body)))
            self.end_headers()
            self.wfile.write(resp.body)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _go

        def log_message(self, fmt, *args):
            pass

    print(
        f"SyncBridge dev stack on {stack.base}\n"
        f"  console      {stack.base}/   (sign in through mock Okta)\n"
        f"  Salesforce   {stack.base}/_sim/salesforce/ui\n"
        f"  Slack        {stack.base}/_sim/slack/ui\n"
        f"  SCIM token   {stack.scim_token}"
    )
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
