"""A Salesforce org simulator for local development and failure testing.

It implements the parts of the REST API the integration uses with the same paths, status codes
and error bodies (OAuth token endpoint, sObject get/patch/create, upsert by external ID, SOQL
query with pagination), plus what the Apex trigger does: every committed change to a Case or
Case_Message__c produces a signed webhook notification in an outbox the harness delivers.

Faults are injected per request from a FaultPlan, including the ambiguous kind: the write is
committed and then the response fails, exactly what happens when a Lambda times out waiting for
Salesforce.
"""

from __future__ import annotations

import json
import random
import re
import string
import threading
import uuid
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse

import httpx

from ..clock import Clock, iso, parse_iso
from .faults import DeliveryPlan, FaultPlan

B62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
CASE_FIELDS = [
    "CaseNumber",
    "Subject",
    "Status",
    "Priority",
    "Origin",
    "Description",
    "AccountName",
    "OwnerName",
    "Last_Slack_Actor__c",
]
MSG_FIELDS = [
    "Case__c",
    "Body__c",
    "Author__c",
    "Source__c",
    "Slack_Message_Key__c",
    "Slack_Channel__c",
    "Slack_TS__c",
]
INTEGRATION_USER = "005Hs00000INTEG"


def _sf_id(prefix: str, n: int) -> str:
    out = ""
    for _ in range(7):
        out = B62[n % 62] + out
        n //= 62
    return prefix + "Hs000" + out + "AAA"


@dataclass
class Outbound:
    deliver_at: float
    payload: dict
    attempt: int = 1


@dataclass
class SalesforceSim:
    clock: Clock
    webhook_secret: str = "sf-webhook-secret"
    instance_url: str = "https://acme-dev.my.salesforce.com"
    api_version: str = "v62.0"
    client_id: str = "sim-sf-client"
    client_secret: str = "sim-sf-secret"
    faults: FaultPlan = field(default_factory=FaultPlan)
    delivery: DeliveryPlan = field(default_factory=DeliveryPlan)
    expire_token_every: int = 0  # invalidate the access token every N API calls
    rng: random.Random = field(default_factory=lambda: random.Random(3))

    def __post_init__(self) -> None:
        self.cases: dict[str, dict] = {}
        self.messages: dict[str, dict] = {}
        self.ext_index: dict[str, str] = {}
        self.tokens: set[str] = set()
        self.refresh_tokens: set[str] = {"sim-refresh-token"}
        self.codes: dict[str, str] = {}
        self.outbox: list[Outbound] = []
        self.counter = 0
        self.case_number = 1000
        self._last_ms = 0
        self.api_calls = Counter()
        self.writes_applied = Counter()
        self.message_creates = Counter()  # (channel, ts) -> number of records created
        self.notifications = 0
        self._queries: dict[str, list[dict]] = {}
        self._lock = threading.RLock()  # one request at a time, like a single org's API

    # --- clock -----------------------------------------------------------------------------------

    def _modstamp(self) -> str:
        ms = int(self.clock.now() * 1000)
        ms = max(ms, self._last_ms + 1)
        self._last_ms = ms
        return iso(ms / 1000)

    def _next_id(self, prefix: str) -> str:
        self.counter += 1
        return _sf_id(prefix, self.counter)

    # --- data changes (used by API handlers and by simulated agents) ------------------------------

    def create_case(self, fields: dict, by: str = "005Hs00000AGENT") -> dict:
        self.case_number += 1
        rec = {
            "Id": self._next_id("500"),
            "CaseNumber": f"{self.case_number:08d}",
            "Status": "New",
            "Priority": "Medium",
            "Origin": "Web",
            **{k: v for k, v in fields.items() if k in CASE_FIELDS},
            "SystemModstamp": self._modstamp(),
            "LastModifiedById": by,
        }
        self.cases[rec["Id"]] = rec
        self._notify("Case", rec, "CREATE")
        return rec

    def update_case(self, case_id: str, fields: dict, by: str = "005Hs00000AGENT") -> dict:
        rec = self.cases[case_id]
        rec.update({k: v for k, v in fields.items() if k in CASE_FIELDS})
        rec["SystemModstamp"] = self._modstamp()
        rec["LastModifiedById"] = by
        self._notify("Case", rec, "UPDATE")
        return rec

    def add_message(self, fields: dict, by: str = "005Hs00000AGENT") -> dict:
        rec = {
            "Id": self._next_id("a0B"),
            **{k: v for k, v in fields.items() if k in MSG_FIELDS},
            "SystemModstamp": self._modstamp(),
            "LastModifiedById": by,
        }
        rec.setdefault("Source__c", "Salesforce")
        self.messages[rec["Id"]] = rec
        if rec.get("Slack_Message_Key__c"):
            self.ext_index[rec["Slack_Message_Key__c"]] = rec["Id"]
        if rec.get("Slack_TS__c"):
            self.message_creates[(rec.get("Slack_Channel__c"), rec["Slack_TS__c"])] += 1
        self._notify("Case_Message__c", rec, "CREATE")
        return rec

    def _update_message(self, msg_id: str, fields: dict, by: str) -> dict:
        rec = self.messages[msg_id]
        rec.update({k: v for k, v in fields.items() if k in MSG_FIELDS})
        rec["SystemModstamp"] = self._modstamp()
        rec["LastModifiedById"] = by
        self._notify("Case_Message__c", rec, "UPDATE")
        return rec

    # --- Apex trigger: outbound notifications -----------------------------------------------------

    def _notify(self, sobject: str, rec: dict, change: str) -> None:
        self.notifications += 1
        fields = {
            k: v for k, v in rec.items() if k not in ("Id", "SystemModstamp", "LastModifiedById")
        }
        payload = {
            "orgId": "00DHs000000SIM1",
            "events": [
                {
                    "eventId": str(uuid.uuid4()),
                    "sobject": sobject,
                    "recordId": rec["Id"],
                    "changeType": change,
                    "systemModstamp": rec["SystemModstamp"],
                    "fields": fields,
                    "lastModifiedById": rec["LastModifiedById"],
                }
            ],
        }
        d = self.delivery
        if d.rng.random() < d.drop:
            d.injected["dropped"] += 1
            return
        when = self.clock.now() + 0.2 + (d.rng.uniform(0, d.max_delay) if d.max_delay else 0)
        self.outbox.append(Outbound(when, payload))
        if d.rng.random() < d.duplicate:  # the queueable retries a callout it thinks failed
            d.injected["duplicated"] += 1
            self.outbox.append(Outbound(when + d.rng.uniform(1, 90), payload, attempt=2))

    def due_notifications(self) -> list[Outbound]:
        now = self.clock.now()
        due = [o for o in self.outbox if o.deliver_at <= now]
        if due:
            self.outbox = [o for o in self.outbox if o.deliver_at > now]
        return due

    # --- HTTP -------------------------------------------------------------------------------------

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            return self._handle(request)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/services/oauth2/"):
            return self._oauth(request, path)
        self.api_calls["total"] += 1
        auth = request.headers.get("authorization", "")
        if auth.removeprefix("Bearer ") not in self.tokens:
            return _err(401, "INVALID_SESSION_ID", "Session expired or invalid")
        if self.expire_token_every and self.api_calls["total"] % self.expire_token_every == 0:
            self.tokens.clear()
            return _err(401, "INVALID_SESSION_ID", "Session expired or invalid")
        write = request.method != "GET"
        fault = self.faults.pick(self.clock.now(), write)
        if fault == "outage" or fault == "error_before":
            return _err(503, "SERVER_UNAVAILABLE", "Service temporarily unavailable")
        if fault == "connect_error":
            raise httpx.ConnectError("connection refused", request=request)
        if fault == "rate_limit":
            return _err(403, "REQUEST_LIMIT_EXCEEDED", "ConcurrentPerOrgLongTxn Limit exceeded.")
        if fault == "lock_error":
            return _err(
                400, "UNABLE_TO_LOCK_ROW", "unable to obtain exclusive access to this record"
            )
        resp = self._route(request, path)
        if fault == "error_after" and resp.status_code < 300:
            return _err(500, "UNKNOWN_EXCEPTION", "An unexpected error occurred")
        if fault == "timeout_after" and resp.status_code < 300:
            raise httpx.ReadTimeout("read timed out", request=request)
        return resp

    def _oauth(self, request: httpx.Request, path: str) -> httpx.Response:
        if path.endswith("/authorize"):  # dev only: auto-approve and redirect back
            q = parse_qs(urlparse(str(request.url)).query)
            code = uuid.uuid4().hex
            self.codes[code] = q.get("code_challenge", [""])[0]
            target = f"{q['redirect_uri'][0]}?code={code}&state={q.get('state', [''])[0]}"
            return httpx.Response(302, headers={"Location": target})
        if path.endswith("/revoke"):
            self.tokens.clear()
            return httpx.Response(200)
        form = parse_qs(request.content.decode())
        grant = form.get("grant_type", [""])[0]
        if grant == "refresh_token" and form.get("refresh_token", [""])[0] in self.refresh_tokens:
            return httpx.Response(200, json=self._issue(refresh=False))
        if grant == "authorization_code" and form.get("code", [""])[0] in self.codes:
            self.codes.pop(form["code"][0])
            return httpx.Response(200, json=self._issue(refresh=True))
        return httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "authentication failure"}
        )

    def _issue(self, refresh: bool) -> dict:
        token = "00DHs000000SIM1!" + uuid.uuid4().hex
        self.tokens.add(token)
        body = {
            "access_token": token,
            "instance_url": self.instance_url,
            "id": "https://login.salesforce.com/id/00DHs000000SIM1/005Hs00000INTEG",
            "token_type": "Bearer",
            "issued_at": str(int(self.clock.now() * 1000)),
            "scope": "api refresh_token",
        }
        if refresh:
            body["refresh_token"] = "sim-refresh-token"
        return body

    def _route(self, request: httpx.Request, path: str) -> httpx.Response:
        base = f"/services/data/{self.api_version}"
        if not path.startswith(base):
            return _err(404, "NOT_FOUND", "The requested resource does not exist")
        rest = path[len(base) :]
        m = re.fullmatch(r"/sobjects/(\w+)/(\w+)/(.+)", rest)
        if m and request.method == "PATCH":  # upsert by external ID
            sobject, ext_field, value = m.group(1), m.group(2), unquote(m.group(3))
            if sobject != "Case_Message__c" or ext_field != "Slack_Message_Key__c":
                return _err(400, "INVALID_FIELD", f"{ext_field} is not an external ID field")
            fields = json.loads(request.content or b"{}")
            self.writes_applied["upsert"] += 1
            existing = self.ext_index.get(value)
            if existing:
                self._update_message(existing, fields, INTEGRATION_USER)
                return httpx.Response(
                    200, json={"id": existing, "success": True, "errors": [], "created": False}
                )
            rec = self.add_message({**fields, "Slack_Message_Key__c": value}, INTEGRATION_USER)
            return httpx.Response(
                201, json={"id": rec["Id"], "success": True, "errors": [], "created": True}
            )
        m = re.fullmatch(r"/sobjects/(\w+)/(\w+)", rest)
        if m:
            sobject, rid = m.group(1), m.group(2)
            table = self.cases if sobject == "Case" else self.messages
            if rid not in table:
                return _err(404, "NOT_FOUND", "The requested resource does not exist")
            if request.method == "GET":
                return httpx.Response(200, json={"attributes": {"type": sobject}, **table[rid]})
            if request.method == "PATCH":
                fields = json.loads(request.content or b"{}")
                self.writes_applied["patch"] += 1
                if sobject == "Case":
                    self.update_case(rid, fields, INTEGRATION_USER)
                else:
                    self._update_message(rid, fields, INTEGRATION_USER)
                return httpx.Response(204)
        m = re.fullmatch(r"/sobjects/(\w+)", rest)
        if m and request.method == "POST":
            fields = json.loads(request.content or b"{}")
            self.writes_applied["create"] += 1
            if m.group(1) == "Case":
                rec = self.create_case(fields, INTEGRATION_USER)
            else:
                rec = self.add_message(fields, INTEGRATION_USER)
            return httpx.Response(201, json={"id": rec["Id"], "success": True, "errors": []})
        if rest == "/query" or rest.startswith("/query/"):
            return self._query(request, rest)
        if rest == "/limits":
            return httpx.Response(
                200,
                json={
                    "DailyApiRequests": {
                        "Max": 100000,
                        "Remaining": 100000 - self.api_calls["total"],
                    }
                },
            )
        return _err(404, "NOT_FOUND", "The requested resource does not exist")

    def _query(self, request: httpx.Request, rest: str) -> httpx.Response:
        if rest.startswith("/query/"):
            cursor = rest.split("/")[-1]
            records = self._queries.pop(cursor, None)
            if records is None:
                return _err(400, "INVALID_QUERY_LOCATOR", "invalid query locator")
            return self._page(records)
        soql = parse_qs(urlparse(str(request.url)).query).get("q", [""])[0]
        m = re.fullmatch(
            r"SELECT (.+) FROM (\w+) WHERE SystemModstamp > (\S+)( AND Source__c != 'Slack')? "
            r"ORDER BY SystemModstamp ASC(?: LIMIT (\d+))?",
            soql.strip(),
        )
        if not m:
            return _err(400, "MALFORMED_QUERY", "unsupported query in simulator")
        sobject, since = m.group(2), parse_iso(m.group(3))
        table = self.cases if sobject == "Case" else self.messages
        rows = [r for r in table.values() if parse_iso(r["SystemModstamp"]) > since]
        if m.group(4):
            rows = [r for r in rows if r.get("Source__c") != "Slack"]
        rows.sort(key=lambda r: r["SystemModstamp"])
        if m.group(5):
            rows = rows[: int(m.group(5))]
        out = []
        for r in rows:
            rec = {
                "attributes": {"type": sobject},
                **{k: v for k, v in r.items() if k not in ("AccountName", "OwnerName")},
            }
            if sobject == "Case":
                rec["Account"] = {"Name": r.get("AccountName")}
                rec["Owner"] = {"Name": r.get("OwnerName")}
            out.append(rec)
        return self._page(out)

    def _page(self, records: list[dict], size: int = 2000) -> httpx.Response:
        body: dict = {
            "totalSize": len(records),
            "done": len(records) <= size,
            "records": records[:size],
        }
        if len(records) > size:
            cursor = f"01gSIM{uuid.uuid4().hex[:10]}-{size}"
            self._queries[cursor] = records[size:]
            body["nextRecordsUrl"] = f"/services/data/{self.api_version}/query/{cursor}"
        return httpx.Response(200, json=body)


def _err(status: int, code: str, message: str) -> httpx.Response:
    return httpx.Response(status, json=[{"message": message, "errorCode": code, "fields": []}])
