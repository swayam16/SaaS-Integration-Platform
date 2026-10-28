"""SCIM 2.0 service provider (RFC 7643/7644) for Okta user and group provisioning.

    /scim/v2/Users          GET (filter, paging) · POST
    /scim/v2/Users/{id}     GET · PUT · PATCH · DELETE
    /scim/v2/Groups         GET (filter, paging, excludedAttributes=members) · POST
    /scim/v2/Groups/{id}    GET · PUT · PATCH · DELETE
    /scim/v2/ServiceProviderConfig, /ResourceTypes, /Schemas

Okta "Push Groups" maps groups to console roles (admins, operators, viewers). Deactivating or
deleting a user in Okta revokes their console sessions at once, and role changes apply to live
sessions too. The bearer token is compared by SHA-256 in constant time; only its hash is
configured.
"""

from __future__ import annotations

import copy
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from ..admin.audit import AuditLog
from ..admin.sessions import ROLE_RANK, Sessions
from ..clock import Clock
from ..config import Settings
from ..crypto import constant_time_equals, sha256_hex
from ..http import Request, Response, Router, json_response
from ..store import ConditionFailed, Store
from .filter import FilterError, Parser, compile_filter

USERS, USERNAMES = "scim_users", "scim_usernames"
GROUPS, GROUPNAMES = "scim_groups", "scim_groupnames"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
CT = "application/scim+json"
READ_ONLY = {"id", "meta", "schemas"}
MULTI = {"emails", "phoneNumbers", "members", "groups", "addresses", "roles"}


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None):
        super().__init__(detail)
        self.status, self.detail, self.scim_type = status, detail, scim_type

    def response(self) -> Response:
        body = {"schemas": [ERROR_SCHEMA], "status": str(self.status), "detail": self.detail}
        if self.scim_type:
            body["scimType"] = self.scim_type
        return json_response(body, self.status, content_type=CT)


def _now_iso(clock: Clock) -> str:
    return datetime.fromtimestamp(clock.now(), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bool(v: Any) -> bool:
    return v.strip().lower() == "true" if isinstance(v, str) else bool(v)


class Directory:
    def __init__(
        self, store: Store, clock: Clock, settings: Settings, sessions: Sessions, audit: AuditLog
    ):
        self.store, self.clock, self.s = store, clock, settings
        self.sessions, self.audit = sessions, audit

    # --- shared ----------------------------------------------------------------------------------

    def _new_id(self) -> str:
        """Time-ordered IDs, so paging through a list is stable between requests."""
        return f"{int(self.clock.now() * 1_000_000):014x}{uuid.uuid4().hex[:18]}"

    def _meta(self, kind: str, rid: str, created: str | None, version: int) -> dict:
        now = _now_iso(self.clock)
        return {
            "resourceType": kind,
            "created": created or now,
            "lastModified": now,
            "location": f"{self.s.base_url}/scim/v2/{kind}s/{rid}",
            "version": f'W/"{version}"',
        }

    def _claim_name(self, index: str, name: str, rid: str) -> None:
        key = name.lower()
        try:
            self.store.put(index, key, {"id": rid}, [("not_exists",)])
        except ConditionFailed as exc:
            owner = (exc.current or {}).get("id")
            table = USERS if index == USERNAMES else GROUPS
            if owner and owner != rid and self.store.get(table, owner) is not None:
                raise ScimError(409, f"{name!r} is already in use", "uniqueness") from None
            self.store.put(index, key, {"id": rid})  # orphaned index entry: reclaim it

    # --- users -------------------------------------------------------------------------------------

    def _clean_user(self, body: dict) -> dict:
        user = {k: copy.deepcopy(v) for k, v in body.items() if k not in READ_ONLY}
        if not str(user.get("userName", "")).strip():
            raise ScimError(400, "userName is required", "invalidValue")
        user["userName"] = str(user["userName"]).strip()
        user["active"] = _bool(user.get("active", True))
        if not user.get("displayName"):
            name = user.get("name") or {}
            user["displayName"] = (
                " ".join(x for x in (name.get("givenName"), name.get("familyName")) if x)
                or user["userName"]
            )
        return user

    def create_user(self, body: dict, actor: str) -> dict:
        user = self._clean_user(body)
        uid = self._new_id()
        self._claim_name(USERNAMES, user["userName"], uid)
        user.update(id=uid, schemas=[USER_SCHEMA], meta=self._meta("User", uid, None, 1))
        self.store.put(USERS, uid, user, [("not_exists",)])
        self.audit.record(actor, "scim.user.create", user["userName"], {"active": user["active"]})
        return self._present_user(user)

    def get_user(self, uid: str) -> dict:
        user = self.store.get(USERS, uid)
        if user is None:
            raise ScimError(404, f"User {uid} not found")
        return user

    def _save_user(self, old: dict, new: dict, actor: str) -> dict:
        if new["userName"].lower() != old["userName"].lower():
            self._claim_name(USERNAMES, new["userName"], old["id"])
            self.store.delete(USERNAMES, old["userName"].lower())
        version = int(re.sub(r"\D", "", old["meta"]["version"]) or 1) + 1
        new.update(
            id=old["id"],
            schemas=[USER_SCHEMA],
            meta=self._meta("User", old["id"], old["meta"]["created"], version),
        )
        self.store.put(USERS, old["id"], new)
        if old.get("active", True) and not new["active"]:
            revoked = self.sessions.revoke_user(old["id"])
            self.audit.record(
                actor, "scim.user.deactivate", new["userName"], {"sessions_revoked": revoked}
            )
        elif not old.get("active", True) and new["active"]:
            self.audit.record(actor, "scim.user.reactivate", new["userName"])
        else:
            self.audit.record(actor, "scim.user.update", new["userName"])
        return self._present_user(new)

    def replace_user(self, uid: str, body: dict, actor: str) -> dict:
        old = self.get_user(uid)
        return self._save_user(old, self._clean_user(body), actor)

    def patch_user(self, uid: str, body: dict, actor: str) -> dict:
        old = self.get_user(uid)
        new = apply_patch(copy.deepcopy(old), body)
        new = {k: v for k, v in new.items() if k not in READ_ONLY}
        new["userName"] = str(new.get("userName", old["userName"])).strip()
        new["active"] = _bool(new.get("active", True))
        return self._save_user(old, new, actor)

    def delete_user(self, uid: str, actor: str) -> None:
        user = self.get_user(uid)
        for gid, group in self.store.list(GROUPS):
            members = [m for m in group.get("members", []) if m.get("value") != uid]
            if len(members) != len(group.get("members", [])):
                self.store.update(GROUPS, gid, {"members": members})
        self.store.delete(USERS, uid)
        self.store.delete(USERNAMES, user["userName"].lower())
        revoked = self.sessions.revoke_user(uid)
        self.audit.record(
            actor, "scim.user.delete", user["userName"], {"sessions_revoked": revoked}
        )

    def list_users(self, flt: str | None) -> list[dict]:
        pred = compile_filter(flt)
        users = [self._present_user(u) for _, u in self.store.list(USERS, limit=100_000)]
        users.sort(key=lambda u: u["id"])
        return [u for u in users if pred(u)]

    def _present_user(self, user: dict) -> dict:
        out = copy.deepcopy(user)
        out["groups"] = [
            {
                "value": gid,
                "display": g["displayName"],
                "$ref": f"{self.s.base_url}/scim/v2/Groups/{gid}",
            }
            for gid, g in self.store.list(GROUPS)
            if any(m.get("value") == user["id"] for m in g.get("members", []))
        ]
        return out

    def find_by_username(self, username: str) -> dict | None:
        idx = self.store.get(USERNAMES, username.lower())
        if not idx:
            return None
        user = self.store.get(USERS, idx["id"])
        return self._present_user(user) if user else None

    def role_for(self, user: dict) -> str:
        role = "viewer"
        for g in user.get("groups", []):
            mapped = self.s.role_groups.get(g.get("display", ""))
            if mapped and ROLE_RANK[mapped] > ROLE_RANK[role]:
                role = mapped
        return role

    # --- groups ------------------------------------------------------------------------------------

    def _clean_group(self, body: dict) -> dict:
        group = {k: copy.deepcopy(v) for k, v in body.items() if k not in READ_ONLY}
        if not str(group.get("displayName", "")).strip():
            raise ScimError(400, "displayName is required", "invalidValue")
        group["members"] = self._valid_members(group.get("members") or [])
        return group

    def _valid_members(self, members: list) -> list[dict]:
        out, seen = [], set()
        for m in members:
            uid = m.get("value") if isinstance(m, dict) else None
            if uid and uid not in seen and self.store.get(USERS, uid) is not None:
                user = self.store.get(USERS, uid)
                out.append({"value": uid, "display": user.get("displayName", user["userName"])})
                seen.add(uid)
        return out

    def create_group(self, body: dict, actor: str) -> dict:
        group = self._clean_group(body)
        gid = self._new_id()
        self._claim_name(GROUPNAMES, group["displayName"], gid)
        group.update(id=gid, schemas=[GROUP_SCHEMA], meta=self._meta("Group", gid, None, 1))
        self.store.put(GROUPS, gid, group, [("not_exists",)])
        self.audit.record(
            actor, "scim.group.create", group["displayName"], {"members": len(group["members"])}
        )
        self._refresh_roles({m["value"] for m in group["members"]})
        return group

    def get_group(self, gid: str) -> dict:
        group = self.store.get(GROUPS, gid)
        if group is None:
            raise ScimError(404, f"Group {gid} not found")
        return group

    def _save_group(self, old: dict, new: dict, actor: str) -> dict:
        if new["displayName"].lower() != old["displayName"].lower():
            self._claim_name(GROUPNAMES, new["displayName"], old["id"])
            self.store.delete(GROUPNAMES, old["displayName"].lower())
        new["members"] = self._valid_members(new.get("members") or [])
        version = int(re.sub(r"\D", "", old["meta"]["version"]) or 1) + 1
        new.update(
            id=old["id"],
            schemas=[GROUP_SCHEMA],
            meta=self._meta("Group", old["id"], old["meta"]["created"], version),
        )
        self.store.put(GROUPS, old["id"], new)
        before = {m["value"] for m in old.get("members", [])}
        after = {m["value"] for m in new["members"]}
        self.audit.record(
            actor,
            "scim.group.update",
            new["displayName"],
            {"added": len(after - before), "removed": len(before - after)},
        )
        self._refresh_roles(before | after)
        return new

    def replace_group(self, gid: str, body: dict, actor: str) -> dict:
        return self._save_group(self.get_group(gid), self._clean_group(body), actor)

    def patch_group(self, gid: str, body: dict, actor: str) -> dict:
        old = self.get_group(gid)
        new = apply_patch(copy.deepcopy(old), body)
        new = {k: v for k, v in new.items() if k not in READ_ONLY}
        new["displayName"] = str(new.get("displayName", old["displayName"])).strip()
        return self._save_group(old, new, actor)

    def delete_group(self, gid: str, actor: str) -> None:
        group = self.get_group(gid)
        self.store.delete(GROUPS, gid)
        self.store.delete(GROUPNAMES, group["displayName"].lower())
        self.audit.record(actor, "scim.group.delete", group["displayName"])
        self._refresh_roles({m["value"] for m in group.get("members", [])})

    def list_groups(self, flt: str | None) -> list[dict]:
        pred = compile_filter(flt)
        groups = [g for _, g in self.store.list(GROUPS, limit=100_000)]
        groups.sort(key=lambda g: g["id"])
        return [g for g in groups if pred(g)]

    def _refresh_roles(self, user_ids: set[str]) -> None:
        for uid in user_ids:
            user = self.store.get(USERS, uid)
            if user is not None:
                self.sessions.update_role(uid, self.role_for(self._present_user(user)))


# --- PATCH ------------------------------------------------------------------------------------------

PATH = re.compile(r"^(?P<attr>[\w$:.-]+?)(?:\[(?P<filter>.+)\])?(?:\.(?P<sub>\w+))?$")


def apply_patch(resource: dict, body: dict) -> dict:
    ops = body.get("Operations") or body.get("operations")
    if not isinstance(ops, list) or not ops:
        raise ScimError(400, "PATCH needs Operations", "invalidSyntax")
    for op in ops:
        kind = str(op.get("op", "")).lower()
        path, value = op.get("path"), op.get("value")
        if kind not in ("add", "replace", "remove"):
            raise ScimError(400, f"unsupported op {op.get('op')!r}", "invalidSyntax")
        if not path:
            if kind == "remove" or not isinstance(value, dict):
                raise ScimError(
                    400,
                    "operation without path needs an object value",
                    "noTarget" if kind == "remove" else "invalidValue",
                )
            for k, v in value.items():
                _set(resource, k, v, kind)
            continue
        if path.lower().startswith("urn:"):
            path = path.rsplit(":", 1)[-1]
        m = PATH.match(path)
        if not m:
            raise ScimError(400, f"invalid path {path!r}", "invalidPath")
        attr, flt, sub = m.group("attr"), m.group("filter"), m.group("sub")
        if flt:
            try:
                pred = Parser(flt).parse()
            except FilterError as exc:
                raise ScimError(400, str(exc), "invalidFilter") from exc
            items = resource.setdefault(attr, [])
            matching = [x for x in items if isinstance(x, dict) and pred(x)]
            if kind == "remove":
                if sub:
                    for x in matching:
                        x.pop(sub, None)
                else:
                    resource[attr] = [x for x in items if x not in matching]
            elif matching:
                for x in matching:
                    if sub:
                        x[sub] = value
                    elif isinstance(value, dict):
                        x.update(value)
            else:  # add/replace on a filter that matches nothing: create the element
                eq = re.match(r'\s*(\w+)\s+eq\s+"([^"]*)"\s*$', flt)
                new = {eq.group(1): eq.group(2)} if eq else {}
                new.update({sub: value} if sub else (value if isinstance(value, dict) else {}))
                items.append(new)
            continue
        if kind == "remove":
            if attr in MULTI and isinstance(value, list):
                drop = {v.get("value") for v in value if isinstance(v, dict)}
                resource[attr] = [x for x in resource.get(attr, []) if x.get("value") not in drop]
            else:
                _remove(resource, path)
        else:
            _set(resource, path, value, kind)
    return resource


def _set(resource: dict, path: str, value: Any, kind: str) -> None:
    if path in READ_ONLY:
        return
    parts = path.split(".")
    target = resource
    for p in parts[:-1]:
        target = target.setdefault(p, {})
    last = parts[-1]
    if last in MULTI and kind == "add" and isinstance(value, list):
        existing = target.setdefault(last, [])
        have = {x.get("value") for x in existing if isinstance(x, dict)}
        existing.extend(v for v in value if not isinstance(v, dict) or v.get("value") not in have)
    elif isinstance(value, dict) and isinstance(target.get(last), dict) and last not in MULTI:
        target[last].update(value)
    else:
        target[last] = value


def _remove(resource: dict, path: str) -> None:
    parts = path.split(".")
    target = resource
    for p in parts[:-1]:
        target = target.get(p, {})
    if isinstance(target, dict):
        target.pop(parts[-1], None)


# --- HTTP ----------------------------------------------------------------------------------------------


def scim_routes(directory: Directory, settings: Settings) -> Router:
    r = Router()
    actor = "okta-scim"

    def authed(fn):
        def wrapper(req: Request) -> Response:
            auth = req.header("authorization")
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            if (
                not settings.scim_token_sha256
                or not token
                or not constant_time_equals(sha256_hex(token), settings.scim_token_sha256)
            ):
                return ScimError(401, "invalid or missing bearer token").response()
            try:
                return fn(req)
            except ScimError as exc:
                return exc.response()
            except FilterError as exc:
                return ScimError(400, str(exc), "invalidFilter").response()

        return wrapper

    def ok(data: Any, status: int = 200, location: str | None = None) -> Response:
        headers = {"Location": location} if location else None
        return json_response(data, status, headers, content_type=CT)

    def body_of(req: Request) -> dict:
        data = req.json()
        if not isinstance(data, dict):
            raise ScimError(400, "body must be a JSON object", "invalidSyntax")
        return data

    def page(req: Request, items: list[dict], exclude: set[str] | None = None) -> Response:
        try:
            start = max(1, int(req.arg("startIndex", "1") or 1))
            count = max(0, min(200, int(req.arg("count", "100") or 100)))
        except ValueError:
            raise ScimError(400, "startIndex and count must be integers", "invalidValue") from None
        chunk = items[start - 1 : start - 1 + count]
        if exclude:
            chunk = [{k: v for k, v in x.items() if k not in exclude} for x in chunk]
        return ok(
            {
                "schemas": [LIST_SCHEMA],
                "totalResults": len(items),
                "startIndex": start,
                "itemsPerPage": len(chunk),
                "Resources": chunk,
            }
        )

    def excluded(req: Request) -> set[str]:
        return {a.strip() for a in (req.arg("excludedAttributes") or "").split(",") if a.strip()}

    @r.route("GET", "/scim/v2/Users")
    @authed
    def list_users(req):
        return page(req, directory.list_users(req.arg("filter")), excluded(req))

    @r.route("POST", "/scim/v2/Users")
    @authed
    def create_user(req):
        user = directory.create_user(body_of(req), actor)
        return ok(user, 201, user["meta"]["location"])

    @r.route("GET", "/scim/v2/Users/{id}")
    @authed
    def get_user(req):
        return ok(directory._present_user(directory.get_user(req.params["id"])))

    @r.route("PUT", "/scim/v2/Users/{id}")
    @authed
    def put_user(req):
        return ok(directory.replace_user(req.params["id"], body_of(req), actor))

    @r.route("PATCH", "/scim/v2/Users/{id}")
    @authed
    def patch_user(req):
        return ok(directory.patch_user(req.params["id"], body_of(req), actor))

    @r.route("DELETE", "/scim/v2/Users/{id}")
    @authed
    def delete_user(req):
        directory.delete_user(req.params["id"], actor)
        return Response(204)

    @r.route("GET", "/scim/v2/Groups")
    @authed
    def list_groups(req):
        return page(req, directory.list_groups(req.arg("filter")), excluded(req))

    @r.route("POST", "/scim/v2/Groups")
    @authed
    def create_group(req):
        group = directory.create_group(body_of(req), actor)
        return ok(group, 201, group["meta"]["location"])

    @r.route("GET", "/scim/v2/Groups/{id}")
    @authed
    def get_group(req):
        g = directory.get_group(req.params["id"])
        return ok({k: v for k, v in g.items() if k not in excluded(req)})

    @r.route("PUT", "/scim/v2/Groups/{id}")
    @authed
    def put_group(req):
        return ok(directory.replace_group(req.params["id"], body_of(req), actor))

    @r.route("PATCH", "/scim/v2/Groups/{id}")
    @authed
    def patch_group(req):
        group = directory.patch_group(req.params["id"], body_of(req), actor)
        return ok(group)

    @r.route("DELETE", "/scim/v2/Groups/{id}")
    @authed
    def delete_group(req):
        directory.delete_group(req.params["id"], actor)
        return Response(204)

    @r.route("GET", "/scim/v2/ServiceProviderConfig")
    @authed
    def spc(req):
        return ok(
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "documentationUri": f"{settings.base_url}/docs/setup-guide#scim",
                "patch": {"supported": True},
                "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
                "filter": {"supported": True, "maxResults": 200},
                "changePassword": {"supported": False},
                "sort": {"supported": False},
                "etag": {"supported": False},
                "authenticationSchemes": [
                    {
                        "type": "oauthbearertoken",
                        "name": "Bearer token",
                        "description": "Static bearer token",
                        "primary": True,
                    }
                ],
                "meta": {"resourceType": "ServiceProviderConfig"},
            }
        )

    @r.route("GET", "/scim/v2/ResourceTypes")
    @authed
    def resource_types(req):
        types = [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "schema": USER_SCHEMA,
                "meta": {"resourceType": "ResourceType"},
            },
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "schema": GROUP_SCHEMA,
                "meta": {"resourceType": "ResourceType"},
            },
        ]
        return ok(
            {
                "schemas": [LIST_SCHEMA],
                "totalResults": 2,
                "startIndex": 1,
                "itemsPerPage": 2,
                "Resources": types,
            }
        )

    @r.route("GET", "/scim/v2/Schemas")
    @authed
    def schemas(req):
        def attr(
            name,
            typ="string",
            multi=False,
            required=False,
            sub=None,
            case_exact=False,
            uniqueness="none",
            mutability="readWrite",
        ):
            a = {
                "name": name,
                "type": typ,
                "multiValued": multi,
                "required": required,
                "caseExact": case_exact,
                "mutability": mutability,
                "returned": "default",
                "uniqueness": uniqueness,
            }
            if sub:
                a["subAttributes"] = sub
            return a

        user = {
            "id": USER_SCHEMA,
            "name": "User",
            "attributes": [
                attr("userName", required=True, uniqueness="server"),
                attr(
                    "name",
                    "complex",
                    sub=[attr("givenName"), attr("familyName"), attr("formatted")],
                ),
                attr("displayName"),
                attr("active", "boolean"),
                attr(
                    "emails",
                    "complex",
                    multi=True,
                    sub=[attr("value"), attr("type"), attr("primary", "boolean")],
                ),
                attr("externalId", case_exact=True),
                attr(
                    "groups",
                    "complex",
                    multi=True,
                    mutability="readOnly",
                    sub=[attr("value"), attr("display")],
                ),
            ],
        }
        group = {
            "id": GROUP_SCHEMA,
            "name": "Group",
            "attributes": [
                attr("displayName", required=True, uniqueness="server"),
                attr("members", "complex", multi=True, sub=[attr("value"), attr("display")]),
                attr("externalId", case_exact=True),
            ],
        }
        for s in (user, group):
            s["schemas"] = ["urn:ietf:params:scim:schemas:core:2.0:Schema"]
            s["meta"] = {"resourceType": "Schema"}
        return ok(
            {
                "schemas": [LIST_SCHEMA],
                "totalResults": 2,
                "startIndex": 1,
                "itemsPerPage": 2,
                "Resources": [user, group],
            }
        )

    return r
