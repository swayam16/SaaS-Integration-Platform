"""SCIM 2.0 filter expressions (RFC 7644 §3.4.2.2).

Supports what Okta, Entra ID and OneLogin send: comparison operators (eq ne co sw ew gt ge lt
le), `pr`, `and`/`or`/`not`, parentheses, dotted attribute paths and value filters on
multi-valued attributes (`emails[type eq "work"].value`). String comparison is
case-insensitive except for `id` and `externalId`, which are case-exact per RFC 7643.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

TOKEN = re.compile(r'\s*(?:(\()|(\))|(\[)|(\])|("(?:[^"\\]|\\.)*")|([A-Za-z0-9_.:$-]+))')
OPS = {"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"}
CASE_EXACT = {"id", "externalid"}


class FilterError(ValueError):
    pass


def tokenize(text: str) -> list[str]:
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise FilterError(f"unexpected character at {pos}")
        out.append(next(g for g in m.groups() if g is not None))
        pos = m.end()
    return out


Pred = Callable[[dict], bool]


class Parser:
    def __init__(self, text: str):
        self.toks = tokenize(text)
        self.i = 0

    def peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> str:
        if self.i >= len(self.toks):
            raise FilterError("unexpected end of filter")
        t = self.toks[self.i]
        self.i += 1
        return t

    def parse(self) -> Pred:
        pred = self.expr()
        if self.peek() is not None:
            raise FilterError(f"unexpected token {self.peek()!r}")
        return pred

    def expr(self) -> Pred:
        left = self.term()
        while (self.peek() or "").lower() == "or":
            self.take()
            right = self.term()
            left = (lambda a, b: lambda r: a(r) or b(r))(left, right)
        return left

    def term(self) -> Pred:
        left = self.factor()
        while (self.peek() or "").lower() == "and":
            self.take()
            right = self.factor()
            left = (lambda a, b: lambda r: a(r) and b(r))(left, right)
        return left

    def factor(self) -> Pred:
        t = self.peek()
        if t == "(":
            self.take()
            inner = self.expr()
            if self.take() != ")":
                raise FilterError("missing )")
            return inner
        if (t or "").lower() == "not":
            self.take()
            inner = self.factor()
            return lambda r: not inner(r)
        path = self.take()
        if self.peek() == "[":  # emails[type eq "work"].value
            self.take()
            depth, sub = 1, []
            while depth:
                tok = self.take()
                depth += tok == "["
                depth -= tok == "]"
                if depth:
                    sub.append(tok)
            sub_pred = Parser(" ".join(sub)).parse()
            rest = ""
            if self.peek() and self.peek().startswith("."):
                rest = self.take()[1:]
            if self.peek() is None or self.peek().lower() in ("and", "or") or self.peek() == ")":
                return lambda r: any(sub_pred(x) for x in _values(r, path) if isinstance(x, dict))
            op = self.take().lower()
            value = None if op == "pr" else _literal(self.take())
            cmp = _comparator(op, rest or path, value)
            return lambda r: any(
                cmp(_get(x, rest) if rest else x)
                for x in _values(r, path)
                if isinstance(x, dict) and sub_pred(x)
            )
        op = self.take().lower()
        if op == "pr":
            return lambda r: any(v not in (None, "", [], {}) for v in _values(r, path))
        if op not in OPS:
            raise FilterError(f"unsupported operator {op!r}")
        value = _literal(self.take())
        cmp = _comparator(op, path, value)
        return lambda r: any(cmp(v) for v in _values(r, path))


def _literal(tok: str) -> Any:
    if tok.startswith('"'):
        return json.loads(tok)
    low = tok.lower()
    if low in ("true", "false"):
        return low == "true"
    if low == "null":
        return None
    try:
        return int(tok) if re.fullmatch(r"-?\d+", tok) else float(tok)
    except ValueError as exc:
        raise FilterError(f"bad value {tok!r}") from exc


def _get(obj: Any, path: str) -> Any:
    for part in path.split(".") if path else []:
        if not isinstance(obj, dict):
            return None
        key = next((k for k in obj if k.lower() == part.lower()), None)
        obj = obj.get(key) if key else None
    return obj


def _values(resource: dict, path: str) -> list[Any]:
    """All values at a path, flattening multi-valued attributes (emails.value)."""
    if ":" in path and path.lower().startswith("urn:"):  # schema-qualified attribute
        path = path.rsplit(":", 1)[-1]
    parts = path.split(".")
    current: list[Any] = [resource]
    for part in parts:
        nxt: list[Any] = []
        for obj in current:
            v = _get(obj, part) if isinstance(obj, dict) else None
            if isinstance(v, list):
                nxt.extend(v)
            elif v is not None:
                nxt.append(v)
        current = nxt
    return current


def _comparator(op: str, path: str, value: Any) -> Callable[[Any], bool]:
    exact = path.split(".")[-1].lower() in CASE_EXACT

    def norm(x: Any) -> Any:
        return x.lower() if isinstance(x, str) and not exact else x

    v = norm(value)

    def cmp(x: Any) -> bool:
        x = norm(x)
        try:
            if op == "eq":
                return x == v
            if op == "ne":
                return x != v
            if op == "co":
                return isinstance(x, str) and str(v) in x
            if op == "sw":
                return isinstance(x, str) and x.startswith(str(v))
            if op == "ew":
                return isinstance(x, str) and x.endswith(str(v))
            if op == "gt":
                return x > v
            if op == "ge":
                return x >= v
            if op == "lt":
                return x < v
            if op == "le":
                return x <= v
        except TypeError:
            return False
        return False

    return cmp


def compile_filter(text: str | None) -> Pred:
    if not text:
        return lambda r: True
    return Parser(text).parse()
