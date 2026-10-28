"""Salesforce REST API client.

Every write this integration makes to Salesforce is idempotent by construction:

* Slack messages become `Case_Message__c` records through an **upsert by external ID**
  (`PATCH /sobjects/Case_Message__c/Slack_Message_Key__c/<channel:ts>`). Repeating the call
  updates the same record instead of inserting a second one.
* Slack button actions become a `PATCH /sobjects/Case/<id>` with absolute field values.

So after an ambiguous failure (timeout, 5xx) the client can retry blindly.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from ..breaker import CircuitBreaker
from ..clock import Clock
from ..errors import AuthExpired, PermanentError, RateLimited, TransientError
from ..oauth import TokenVault
from ..retry import RetryPolicy, RetryStats
from .auth import SalesforceAuth

PROVIDER = "salesforce"


class SalesforceClient:
    def __init__(
        self,
        http: httpx.Client,
        vault: TokenVault,
        auth: SalesforceAuth,
        api_version: str,
        clock: Clock,
        retry: RetryPolicy | None = None,
    ):
        self.http, self.vault, self.auth = http, vault, auth
        self.api_version, self.clock = api_version, clock
        self.retry = retry or RetryPolicy()
        self.breaker = CircuitBreaker("Salesforce", clock)
        self.stats = RetryStats()
        self.calls = 0

    # --- transport ------------------------------------------------------------------------------

    def _send(self, method: str, path: str, json: Any = None, params: dict | None = None) -> Any:
        self.breaker.before_call()
        try:
            result = self._send_raw(method, path, json, params)
        except RateLimited:
            raise
        except TransientError:
            self.breaker.failure()
            raise
        self.breaker.success()
        return result

    def _send_raw(
        self, method: str, path: str, json: Any = None, params: dict | None = None
    ) -> Any:
        tokens = self.vault.load(PROVIDER)
        url = path if path.startswith("http") else tokens["instance_url"] + path
        self.calls += 1
        try:
            resp = self.http.request(
                method,
                url,
                json=json,
                params=params,
                headers={
                    "Authorization": f"Bearer {tokens['access_token']}",
                    "Accept": "application/json",
                    "Sforce-Call-Options": "client=SyncBridge",
                },
                timeout=15.0,
            )
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            raise TransientError(f"connect failed: {exc}", ambiguous=False) from exc
        except httpx.TimeoutException as exc:
            raise TransientError(f"timeout: {exc}", ambiguous=method != "GET") from exc
        except httpx.TransportError as exc:
            raise TransientError(f"transport: {exc}", ambiguous=method != "GET") from exc
        return self._parse(resp, tokens, method)

    def _parse(self, resp: httpx.Response, tokens: dict, method: str) -> Any:
        if resp.status_code in (200, 201):
            return resp.json() if resp.content else {}
        if resp.status_code == 204:
            return {}
        errors = _errors(resp)
        code = errors[0].get("errorCode", "") if errors else ""
        message = errors[0].get("message", resp.text[:200]) if errors else resp.text[:200]
        if resp.status_code == 401 or code == "INVALID_SESSION_ID":
            raise AuthExpired(tokens["access_token"])
        if code == "REQUEST_LIMIT_EXCEEDED" or resp.status_code == 429:
            # Daily API limit or concurrent request limit: back off for a while.
            raise RateLimited(
                f"Salesforce limit: {message}",
                retry_after=float(resp.headers.get("Retry-After", 60)),
            )
        if code == "UNABLE_TO_LOCK_ROW":
            raise TransientError(message, ambiguous=False)
        if resp.status_code >= 500:
            raise TransientError(
                f"Salesforce {resp.status_code}: {message}", ambiguous=method != "GET"
            )
        raise PermanentError(f"Salesforce {resp.status_code} {code}: {message}")

    def _call(self, method: str, path: str, json: Any = None, params: dict | None = None) -> Any:
        def attempt() -> Any:
            try:
                return self._send(method, path, json, params)
            except AuthExpired as exc:
                self.vault.refresh(PROVIDER, str(exc), self.auth.refresh)
                return self._send(method, path, json, params)

        return self.retry.run(attempt, self.clock, self.stats)

    @property
    def base(self) -> str:
        return f"/services/data/{self.api_version}"

    # --- API --------------------------------------------------------------------------------------

    def get_record(self, sobject: str, record_id: str, fields: list[str] | None = None) -> dict:
        params = {"fields": ",".join(fields)} if fields else None
        return self._call("GET", f"{self.base}/sobjects/{sobject}/{record_id}", params=params)

    def update_record(self, sobject: str, record_id: str, fields: dict) -> None:
        self._call("PATCH", f"{self.base}/sobjects/{sobject}/{record_id}", json=fields)

    def upsert(self, sobject: str, external_field: str, external_value: str, fields: dict) -> dict:
        """Returns {"id": ..., "created": bool}."""
        path = f"{self.base}/sobjects/{sobject}/{external_field}/{quote(external_value, safe='')}"
        result = self._call("PATCH", path, json=fields) or {}
        return {"id": result.get("id"), "created": bool(result.get("created", False))}

    def query(self, soql: str, max_records: int = 10_000) -> list[dict]:
        out: list[dict] = []
        page = self._call("GET", f"{self.base}/query", params={"q": soql})
        while True:
            out.extend(page.get("records", []))
            nxt = page.get("nextRecordsUrl")
            if not nxt or len(out) >= max_records:
                return out[:max_records]
            page = self._call("GET", nxt)

    def limits(self) -> dict:
        return self._call("GET", f"{self.base}/limits")


def _errors(resp: httpx.Response) -> list[dict]:
    try:
        body = resp.json()
    except ValueError:
        return []
    if isinstance(body, list):
        return [e for e in body if isinstance(e, dict)]
    if isinstance(body, dict):
        if "errorCode" in body:
            return [body]
        if "error" in body:
            return [{"errorCode": body["error"], "message": body.get("error_description", "")}]
    return []
