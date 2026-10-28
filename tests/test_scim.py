"""SCIM 2.0 server, following the request sequence Okta's provisioning sends (and Entra ID's
PATCH quirks)."""

import json

import pytest
from conftest import SCIM_TOKEN

from syncbridge.admin.audit import AuditLog
from syncbridge.admin.sessions import Sessions
from syncbridge.http import Request
from syncbridge.scim.filter import FilterError, compile_filter
from syncbridge.scim.server import Directory, scim_routes
from syncbridge.store.memory import MemoryStore


@pytest.fixture
def env(settings, clock):
    store = MemoryStore(clock)
    sessions = Sessions(store, clock, settings)
    directory = Directory(store, clock, settings, sessions, AuditLog(store, clock))
    return directory, sessions, scim_routes(directory, settings)


def call(router, method, path, body=None, token=SCIM_TOKEN, query=""):
    from urllib.parse import parse_qs

    req = Request(
        method,
        path,
        query=parse_qs(query),
        body=json.dumps(body).encode() if body else b"",
        headers={"authorization": f"Bearer {token}", "content-type": "application/scim+json"},
    )
    resp = router.dispatch(req)
    return resp.status, (json.loads(resp.body) if resp.body else None)


OKTA_USER = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "avery@acme.example",
    "name": {"givenName": "Avery", "familyName": "Chen"},
    "emails": [{"primary": True, "value": "avery@acme.example", "type": "work"}],
    "displayName": "Avery Chen",
    "locale": "en-US",
    "externalId": "00u1abcd",
    "groups": [],
    "password": "ignored",
    "active": True,
}


def test_auth_required(env):
    _, _, r = env
    assert call(r, "GET", "/scim/v2/Users", token="wrong")[0] == 401
    assert call(r, "GET", "/scim/v2/Users", token="")[0] == 401


def test_okta_user_lifecycle(env):
    directory, sessions, r = env
    # Okta first checks whether the user exists
    status, body = call(
        r,
        "GET",
        "/scim/v2/Users",
        query='filter=userName eq "avery@acme.example"&startIndex=1&count=100',
    )
    assert status == 200 and body["totalResults"] == 0 and body["Resources"] == []
    status, user = call(r, "POST", "/scim/v2/Users", OKTA_USER)
    assert status == 201 and user["id"] and user["active"] is True
    assert user["meta"]["location"].endswith(f"/scim/v2/Users/{user['id']}")
    assert "password" in user  # stored as sent; never returned by real IdPs' reads, never used
    # duplicate userName (case-insensitive) -> 409 uniqueness
    status, err = call(r, "POST", "/scim/v2/Users", {**OKTA_USER, "userName": "AVERY@acme.example"})
    assert status == 409 and err["scimType"] == "uniqueness"
    status, body = call(r, "GET", "/scim/v2/Users", query='filter=userName eq "AVERY@ACME.EXAMPLE"')
    assert body["totalResults"] == 1
    # profile update with PUT
    status, upd = call(
        r,
        "PUT",
        f"/scim/v2/Users/{user['id']}",
        {**OKTA_USER, "name": {"givenName": "Avery", "familyName": "Chen-Li"}},
    )
    assert (
        status == 200
        and upd["name"]["familyName"] == "Chen-Li"
        and upd["meta"]["version"] == 'W/"2"'
    )
    # a live console session gets revoked on deactivation
    sessions.create(user["id"], "avery@acme.example", "Avery", "admin")
    status, off = call(
        r,
        "PATCH",
        f"/scim/v2/Users/{user['id']}",
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "value": {"active": False}}],
        },
    )
    assert status == 200 and off["active"] is False
    assert sessions.revoke_user(user["id"]) == 0  # already revoked by the PATCH
    # unknown id
    assert call(r, "GET", "/scim/v2/Users/does-not-exist")[0] == 404
    assert call(r, "DELETE", f"/scim/v2/Users/{user['id']}")[0] == 204
    assert call(r, "GET", f"/scim/v2/Users/{user['id']}")[0] == 404


def test_entra_style_patch(env):
    _, _, r = env
    _, user = call(r, "POST", "/scim/v2/Users", OKTA_USER)
    status, upd = call(
        r,
        "PATCH",
        f"/scim/v2/Users/{user['id']}",
        {
            "Operations": [
                {"op": "Replace", "path": "name.givenName", "value": "Ave"},
                {
                    "op": "Replace",
                    "path": 'emails[type eq "work"].value',
                    "value": "ave@acme.example",
                },
                {
                    "op": "Add",
                    "path": 'phoneNumbers[type eq "mobile"].value',
                    "value": "+1 555 0100",
                },
                {"op": "Replace", "path": "active", "value": "False"},
                {"op": "Replace", "path": "userName", "value": "ave@acme.example"},
            ]
        },
    )
    assert status == 200
    assert upd["name"]["givenName"] == "Ave" and upd["active"] is False
    assert upd["emails"][0]["value"] == "ave@acme.example"
    assert upd["phoneNumbers"] == [{"type": "mobile", "value": "+1 555 0100"}]
    # renaming frees the old userName and claims the new one
    assert (
        call(r, "GET", "/scim/v2/Users", query='filter=userName eq "avery@acme.example"')[1][
            "totalResults"
        ]
        == 0
    )
    assert (
        call(r, "POST", "/scim/v2/Users", {**OKTA_USER, "userName": "ave@acme.example"})[0] == 409
    )


def test_groups_push_and_roles(env):
    directory, sessions, r = env
    _, a = call(r, "POST", "/scim/v2/Users", OKTA_USER)
    _, b = call(
        r,
        "POST",
        "/scim/v2/Users",
        {**OKTA_USER, "userName": "jordan@acme.example", "externalId": "00u2"},
    )
    status, g = call(
        r,
        "POST",
        "/scim/v2/Groups",
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "SyncBridge Operators",
            "members": [{"value": a["id"]}, {"value": "ghost"}],
        },
    )
    assert status == 201 and [m["value"] for m in g["members"]] == [a["id"]]
    raw, sess = sessions.create(b["id"], "jordan@acme.example", "Jordan", "viewer")
    # Okta push: add a member
    status, g2 = call(
        r,
        "PATCH",
        f"/scim/v2/Groups/{g['id']}",
        {
            "Operations": [
                {"op": "add", "path": "members", "value": [{"value": b["id"], "display": "jordan"}]}
            ]
        },
    )
    assert {m["value"] for m in g2["members"]} == {a["id"], b["id"]}
    assert sessions.get(raw).role == "operator"  # live session picked up the new role
    # Okta push: rename the group to the admin group
    call(
        r,
        "PATCH",
        f"/scim/v2/Groups/{g['id']}",
        {
            "Operations": [
                {"op": "replace", "value": {"id": g["id"], "displayName": "SyncBridge Admins"}}
            ]
        },
    )
    assert sessions.get(raw).role == "admin"
    # remove with a value filter path
    call(
        r,
        "PATCH",
        f"/scim/v2/Groups/{g['id']}",
        {"Operations": [{"op": "remove", "path": f'members[value eq "{b["id"]}"]'}]},
    )
    assert sessions.get(raw).role == "viewer"
    # Okta style remove: path members with a value list
    call(
        r,
        "PATCH",
        f"/scim/v2/Groups/{g['id']}",
        {"Operations": [{"op": "remove", "path": "members", "value": [{"value": a["id"]}]}]},
    )
    _, g3 = call(r, "GET", f"/scim/v2/Groups/{g['id']}")
    assert g3["members"] == []
    _, lst = call(
        r, "GET", "/scim/v2/Groups", query="excludedAttributes=members&startIndex=1&count=1"
    )
    assert lst["totalResults"] == 1 and "members" not in lst["Resources"][0]
    _, user = call(r, "GET", f"/scim/v2/Users/{a['id']}")
    assert user["groups"] == []
    assert call(r, "POST", "/scim/v2/Groups", {"displayName": "syncbridge admins"})[0] == 409
    assert call(r, "DELETE", f"/scim/v2/Groups/{g['id']}")[0] == 204


def test_deleting_user_removes_membership(env):
    _, _, r = env
    _, a = call(r, "POST", "/scim/v2/Users", OKTA_USER)
    _, g = call(
        r,
        "POST",
        "/scim/v2/Groups",
        {"displayName": "SyncBridge Admins", "members": [{"value": a["id"]}]},
    )
    call(r, "DELETE", f"/scim/v2/Users/{a['id']}")
    assert call(r, "GET", f"/scim/v2/Groups/{g['id']}")[1]["members"] == []


def test_paging_and_discovery(env):
    _, _, r = env
    for i in range(5):
        call(r, "POST", "/scim/v2/Users", {**OKTA_USER, "userName": f"u{i}@acme.example"})
    _, page = call(r, "GET", "/scim/v2/Users", query="startIndex=3&count=2")
    assert page["totalResults"] == 5 and page["startIndex"] == 3 and page["itemsPerPage"] == 2
    assert [u["userName"] for u in page["Resources"]] == ["u2@acme.example", "u3@acme.example"]
    assert call(r, "GET", "/scim/v2/ServiceProviderConfig")[1]["patch"]["supported"] is True
    assert call(r, "GET", "/scim/v2/ResourceTypes")[1]["totalResults"] == 2
    assert {s["name"] for s in call(r, "GET", "/scim/v2/Schemas")[1]["Resources"]} == {
        "User",
        "Group",
    }
    status, err = call(r, "GET", "/scim/v2/Users", query='filter=userName zz "x"')
    assert status == 400 and err["scimType"] == "invalidFilter"


def test_patch_validation(env):
    _, _, r = env
    _, a = call(r, "POST", "/scim/v2/Users", OKTA_USER)
    assert call(r, "PATCH", f"/scim/v2/Users/{a['id']}", {"Operations": []})[0] == 400
    assert call(r, "PATCH", f"/scim/v2/Users/{a['id']}", {"Operations": [{"op": "move"}]})[0] == 400
    assert call(r, "POST", "/scim/v2/Users", {"name": {"givenName": "x"}})[0] == 400


@pytest.mark.parametrize(
    "expr,expected",
    [
        ('userName eq "AVERY@acme.example"', True),
        ('userName sw "avery" and active eq true', True),
        ('emails[type eq "work"].value co "acme"', True),
        ('emails[type eq "home"]', False),
        ('externalId eq "00U1ABCD"', False),  # externalId is case-exact
        ("not (active eq false) or title pr", True),
        ("title pr", False),
    ],
)
def test_filters(expr, expected):
    assert compile_filter(expr)(OKTA_USER) is expected


def test_bad_filters():
    for expr in ("userName eq", 'userName xx "a"', '(userName eq "a"', 'userName eq "a" extra'):
        with pytest.raises(FilterError):
            compile_filter(expr)
