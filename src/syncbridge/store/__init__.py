"""Key-value storage with conditional writes.

Everything that has to be exactly-once (idempotency claims, record locks, Slack message
mappings, OAuth state, SAML replay cache) is built on a conditional write: "put this item only
if it does not exist" or "update only if attribute X still equals Y". DynamoDB provides this
natively (ConditionExpression); the in-memory store implements the same semantics for local
runs and tests, and both pass the same contract tests.

Conditions are a list of tuples, all of which must hold:

    ("not_exists",)              item does not exist
    ("exists",)                  item exists
    ("eq", attr, value)          attribute equals value
    ("ne", attr, value)          attribute missing or not equal
    ("lt_or_missing", attr, v)   attribute missing or < v
    ("le", attr, value)          attribute exists and <= value
"""

from __future__ import annotations

from typing import Any, Protocol

Condition = tuple
Item = dict[str, Any]


class ConditionFailed(Exception):
    def __init__(self, table: str, key: str, current: Item | None = None):
        super().__init__(f"condition failed on {table}/{key}")
        self.current = current


class Store(Protocol):
    def get(self, table: str, key: str) -> Item | None: ...

    def put(
        self,
        table: str,
        key: str,
        item: Item,
        conditions: list[Condition] | None = None,
        ttl: float | None = None,
    ) -> None: ...

    def update(
        self,
        table: str,
        key: str,
        changes: Item,
        conditions: list[Condition] | None = None,
        remove: list[str] | None = None,
        ttl: float | None = None,
    ) -> Item: ...

    def delete(self, table: str, key: str, conditions: list[Condition] | None = None) -> None: ...

    def increment(self, table: str, key: str, attr: str, amount: int = 1) -> int: ...

    def list(
        self, table: str, prefix: str = "", limit: int = 1000, reverse: bool = False
    ) -> list[tuple[str, Item]]: ...


def check(conditions: list[Condition] | None, current: Item | None) -> bool:
    for cond in conditions or []:
        op = cond[0]
        if op == "not_exists":
            if current is not None:
                return False
        elif op == "exists":
            if current is None:
                return False
        else:
            attr, value = cond[1], cond[2]
            have = None if current is None else current.get(attr)
            if op == "eq" and (current is None or attr not in current or have != value):
                return False
            if op == "ne" and current is not None and attr in current and have == value:
                return False
            if op == "lt_or_missing" and have is not None and not have < value:
                return False
            if op == "le" and (have is None or not have <= value):
                return False
    return True
