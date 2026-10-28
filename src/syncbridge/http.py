"""Minimal HTTP layer shared by the Lambda handlers, the local dev server and the simulators.

Lambda functions sit behind an API Gateway HTTP API (payload format 2.0). `Request.from_apigw`
and `Response.to_apigw` convert to and from that event shape, so the same route functions run
unchanged in Lambda, in the local dev server and inside tests.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qs, urlencode

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


class HttpError(Exception):
    def __init__(self, status: int, message: str, body: dict | None = None):
        super().__init__(message)
        self.status, self.message, self.body = status, message, body


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, list[str]] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)  # lower-cased names
    body: bytes = b""
    cookies: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)  # path parameters
    source_ip: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    def arg(self, name: str, default: str | None = None) -> str | None:
        values = self.query.get(name)
        return values[0] if values else default

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def json(self) -> Any:
        try:
            return json.loads(self.body or b"null")
        except json.JSONDecodeError as exc:
            raise HttpError(400, "body is not valid JSON") from exc

    def form(self) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(self.body.decode(), keep_blank_values=True).items()}

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @classmethod
    def from_apigw(cls, event: dict) -> Request:
        body = event.get("body") or ""
        raw = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode()
        cookies: dict[str, str] = {}
        for c in event.get("cookies") or []:
            name, _, value = c.partition("=")
            cookies[name.strip()] = value.strip()
        headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
        if not cookies and "cookie" in headers:
            cookies = parse_cookie_header(headers["cookie"])
        ctx = event.get("requestContext") or {}
        http = ctx.get("http") or {}
        return cls(
            method=http.get("method", "GET").upper(),
            path=event.get("rawPath") or http.get("path") or "/",
            query=parse_qs(event.get("rawQueryString") or "", keep_blank_values=True),
            headers=headers,
            body=raw,
            cookies=cookies,
            source_ip=http.get("sourceIp", ""),
        )


def parse_cookie_header(value: str) -> dict[str, str]:
    jar = SimpleCookie()
    try:
        jar.load(value)
    except Exception:
        return {}
    return {k: m.value for k, m in jar.items()}


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)

    def to_apigw(self) -> dict:
        try:
            text, b64 = self.body.decode("utf-8"), False
        except UnicodeDecodeError:
            text, b64 = base64.b64encode(self.body).decode(), True
        return {
            "statusCode": self.status,
            "headers": {**SECURITY_HEADERS, **self.headers},
            "cookies": self.cookies,
            "body": text,
            "isBase64Encoded": b64,
        }

    def json(self) -> Any:
        return json.loads(self.body or b"null")


def json_response(
    data: Any,
    status: int = 200,
    headers: dict | None = None,
    content_type: str = "application/json",
) -> Response:
    return Response(
        status,
        json.dumps(data, default=str).encode(),
        {"Content-Type": content_type, "Cache-Control": "no-store", **(headers or {})},
    )


def text_response(text: str, status: int = 200, content_type: str = "text/plain") -> Response:
    return Response(status, text.encode(), {"Content-Type": f"{content_type}; charset=utf-8"})


def redirect(location: str, status: int = 302, cookies: list[str] | None = None) -> Response:
    return Response(status, b"", {"Location": location, "Cache-Control": "no-store"}, cookies or [])


def html_response(html: str, status: int = 200) -> Response:
    return Response(
        status,
        html.encode(),
        {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"},
    )


Handler = Callable[[Request], Response]


class Router:
    def __init__(self) -> None:
        self.routes: list[tuple[str, re.Pattern, Handler]] = []

    def route(self, method: str, pattern: str) -> Callable[[Handler], Handler]:
        regex = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern) + "/?$")

        def deco(fn: Handler) -> Handler:
            self.routes.append((method.upper(), regex, fn))
            return fn

        return deco

    def handles(self, path: str) -> bool:
        return any(regex.match(path) for _, regex, _ in self.routes)

    def include(self, other: Router) -> None:
        self.routes.extend(other.routes)

    def dispatch(self, req: Request) -> Response:
        allowed = False
        for method, regex, fn in self.routes:
            m = regex.match(req.path)
            if not m:
                continue
            allowed = True
            if method != req.method:
                continue
            req.params = m.groupdict()
            try:
                return fn(req)
            except HttpError as exc:
                return json_response(exc.body or {"error": exc.message}, exc.status)
        if allowed:
            return json_response({"error": "method not allowed"}, 405)
        return json_response({"error": "not found"}, 404)

    def lambda_handler(self, event: dict, context: Any = None) -> dict:
        return self.dispatch(Request.from_apigw(event)).to_apigw()


def qs(params: dict) -> str:
    return urlencode({k: v for k, v in params.items() if v is not None})
