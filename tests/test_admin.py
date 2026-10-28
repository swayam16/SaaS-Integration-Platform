"""Console backend end to end: SAML login through the mock Okta, sessions, CSRF, roles, SCIM
deactivation, OAuth connections and dead-letter replay. Runs the dev stack in-process."""

import json
import re
from urllib.parse import parse_qs, urlparse

import pytest

from syncbridge.devserver import DevStack
from syncbridge.http import Request, parse_cookie_header
from syncbridge.saml.mock_idp import MockIdP


@pytest.fixture
def stack():
    return DevStack(port=8099, demo=False)


def req(stack, method, path, cookie=None, body=None, headers=None, form=None):
    query = {}
    if "?" in path:
        path, qs = path.split("?", 1)
        query = parse_qs(qs, keep_blank_values=True)
    raw = b""
    h = dict(headers or {})
    if form is not None:
        from urllib.parse import urlencode

        raw = urlencode(form).encode()
        h["content-type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        raw = json.dumps(body).encode()
        h["content-type"] = "application/json"
    cookies = parse_cookie_header(cookie) if cookie else {}
    return stack.dispatch(Request(method, path, query, h, raw, cookies))


def login(stack, email):
    start = req(stack, "GET", "/saml/login?next=/%23/overview")
    assert start.status == 302
    loc = urlparse(start.headers["Location"])
    q = parse_qs(loc.query)
    authn = MockIdP.parse_authn_request(q["SAMLRequest"][0])
    page = req(stack, "GET", loc.path + "?" + loc.query)
    assert email in page.body.decode() or email.startswith("riley")
    posted = req(
        stack,
        "POST",
        "/_idp/sso",
        form={
            "user": email,
            "request_id": authn["id"],
            "acs": authn["acs"],
            "audience": authn["issuer"],
            "RelayState": q["RelayState"][0],
        },
    )
    saml_response = re.search(r'name="SAMLResponse" value="([^"]+)"', posted.body.decode()).group(1)
    acs = req(
        stack,
        "POST",
        "/saml/acs",
        form={"SAMLResponse": saml_response, "RelayState": q["RelayState"][0]},
    )
    return acs


def session_cookie(resp):
    assert resp.status == 303, resp.body
    assert resp.headers["Location"] == "/#/overview"
    cookie = resp.cookies[0]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    return cookie.split(";")[0]


def me(stack, cookie):
    r = req(stack, "GET", "/api/me", cookie)
    return r.status, json.loads(r.body)


def test_admin_login_session_and_csrf(stack):
    cookie = session_cookie(login(stack, "avery@acme.example"))
    status, info = me(stack, cookie)
    assert status == 200 and info["role"] == "admin" and info["email"] == "avery@acme.example"
    csrf = info["csrf"]
    body = {"channel_id": "C0NEWCHAN1"}
    assert req(stack, "PUT", "/api/settings", cookie, body).status == 403  # no CSRF token
    assert (
        req(
            stack,
            "PUT",
            "/api/settings",
            cookie,
            body,
            {"x-csrf-token": csrf, "origin": "https://evil.example"},
        ).status
        == 403
    )
    ok = req(stack, "PUT", "/api/settings", cookie, body, {"x-csrf-token": csrf})
    assert ok.status == 200 and json.loads(ok.body)["channel_id"] == "C0NEWCHAN1"
    assert (
        req(
            stack, "PUT", "/api/settings", cookie, {"channel_id": "bad"}, {"x-csrf-token": csrf}
        ).status
        == 400
    )
    actions = [a["action"] for a in json.loads(req(stack, "GET", "/api/audit", cookie).body)]
    assert "auth.login" in actions and "settings.update" in actions
    out = req(stack, "POST", "/api/logout", cookie, {}, {"x-csrf-token": csrf})
    assert out.status == 200 and "Max-Age=0" in out.cookies[0]
    assert me(stack, cookie)[0] == 401


def test_roles_from_okta_groups(stack):
    viewer = session_cookie(login(stack, "sam@acme.example"))
    _, info = me(stack, viewer)
    assert info["role"] == "viewer"
    assert req(stack, "GET", "/api/overview", viewer).status == 200
    assert req(stack, "GET", "/api/audit", viewer).status == 403
    assert (
        req(stack, "POST", "/api/reconcile", viewer, {}, {"x-csrf-token": info["csrf"]}).status
        == 403
    )
    operator = session_cookie(login(stack, "jordan@acme.example"))
    _, op = me(stack, operator)
    assert op["role"] == "operator"
    assert (
        req(
            stack,
            "PUT",
            "/api/settings",
            operator,
            {"channel_id": "C0NEWCHAN1"},
            {"x-csrf-token": op["csrf"]},
        ).status
        == 403
    )
    assert req(stack, "GET", "/api/users", operator).status == 403


def test_unprovisioned_and_deactivated_users_are_refused(stack):
    resp = login(stack, "intruder@other.example")
    assert resp.status == 403 and b"not been provisioned" in resp.body
    users = {u["userName"]: u for u in stack.admin.directory.list_users(None)}
    riley = users["riley@acme.example"]
    assert riley["active"] is False
    saml = stack.idp.response(
        name_id="riley@acme.example",
        acs_url=stack.settings.acs_url,
        audience=stack.settings.sp_entity_id,
    )
    stack.settings.saml_allow_idp_initiated = True
    resp = req(stack, "POST", "/saml/acs", form={"SAMLResponse": saml})
    assert resp.status == 403 and b"deactivated" in resp.body


def test_scim_deactivation_ends_live_session(stack):
    cookie = session_cookie(login(stack, "avery@acme.example"))
    assert me(stack, cookie)[0] == 200
    avery = next(
        u for u in stack.admin.directory.list_users(None) if u["userName"] == "avery@acme.example"
    )
    r = req(
        stack,
        "PATCH",
        f"/scim/v2/Users/{avery['id']}",
        body={"Operations": [{"op": "replace", "value": {"active": False}}]},
        headers={"authorization": f"Bearer {stack.scim_token}"},
    )
    assert r.status == 200
    assert me(stack, cookie)[0] == 401


def test_oauth_connect_both_apps(stack):
    cookie = session_cookie(login(stack, "avery@acme.example"))
    _, info = me(stack, cookie)
    h = {"x-csrf-token": info["csrf"]}
    for provider in ("salesforce", "slack"):
        start = req(stack, "POST", f"/api/connections/{provider}/start", cookie, {}, h)
        url = json.loads(start.body)["url"]
        if provider == "salesforce":
            q = parse_qs(urlparse(url).query)
            assert q["code_challenge_method"] == ["S256"] and q["scope"] == ["api refresh_token"]
        authorize = req(stack, "GET", url.replace(stack.base, ""))
        callback = authorize.headers["Location"].replace(stack.base, "")
        done = req(stack, "GET", callback, cookie)
        assert (
            done.status == 302
            and done.headers["Location"] == f"/#/connections?connected={provider}"
        )
        # the state is single-use
        again = req(stack, "GET", callback, cookie)
        assert again.status == 400
    conns = json.loads(req(stack, "GET", "/api/connections", cookie).body)
    assert conns["salesforce"]["instance_url"].endswith("salesforce.com")
    assert conns["slack"]["team_id"] == stack.slack.team_id
    # tokens are encrypted at rest
    raw = stack.platform.store.get("tokens", "salesforce")
    assert "access_token" not in json.dumps(raw)
    # a viewer can't use someone else's callback
    viewer = session_cookie(login(stack, "sam@acme.example"))
    assert req(stack, "GET", "/oauth/slack/callback?code=x&state=y", viewer).status == 403
    assert req(stack, "DELETE", "/api/connections/slack", cookie, {}, h).status == 200
    assert json.loads(req(stack, "GET", "/api/connections", cookie).body)["slack"] is None


def test_dead_letter_replay_and_discard(stack):
    p = stack.platform
    p.store.put("settings", "sync", {"channel_id": "C0SUPPORT1"})
    body = {
        "source": "salesforce",
        "kind": "record_change",
        "sobject": "Case",
        "record_id": "500Hs00000ABCDEAAA",
        "modstamp": "2026-10-28T12:00:00.000Z",
        "fields": {"CaseNumber": "1", "Subject": "x", "Status": "New", "Priority": "Low"},
    }
    outcome = p.worker.handle(body)  # Slack not connected -> permanent error -> dead letter
    assert outcome.dead_lettered and "not connected" in outcome.error
    op = session_cookie(login(stack, "jordan@acme.example"))
    _, info = me(stack, op)
    dls = json.loads(req(stack, "GET", "/api/deadletters", op).body)
    assert len(dls) == 1 and dls[0]["summary"].startswith("Case 500")
    assert (
        req(
            stack,
            "DELETE",
            f"/api/deadletters/{dls[0]['id']}",
            op,
            {},
            {"x-csrf-token": info["csrf"]},
        ).status
        == 403
    )
    r = req(
        stack,
        "POST",
        f"/api/deadletters/{dls[0]['id']}/replay",
        op,
        {},
        {"x-csrf-token": info["csrf"]},
    )
    assert r.status == 200 and p.queue.depth() == 1
    assert json.loads(req(stack, "GET", "/api/deadletters", op).body) == []


def test_relay_state_cannot_redirect_off_site(stack):
    from syncbridge.admin.api import _safe_next

    assert _safe_next("//evil.example/x") == "/"
    assert _safe_next("https://evil.example") == "/"
    assert _safe_next("/\\evil.example") == "/"
    assert _safe_next("/#/deadletters") == "/#/deadletters"


def test_sp_metadata_endpoint(stack):
    r = req(stack, "GET", "/saml/metadata")
    assert r.status == 200 and stack.settings.acs_url.encode() in r.body
