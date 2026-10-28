"""DynamoDB implementation of the Store protocol (single-table design).

    pk                     sk          used for
    -------------------    --------    -----------------------------------------------
    "<table>#<key>"        "-"         point lookups: idempotency, locks, mappings, tokens
    "<table>"              "<key>"     listable tables: users, groups, audit, dead letters

Expiry uses the table's TTL attribute `ttl`. DynamoDB deletes expired items lazily (up to a
couple of days later), so reads and conditions also treat `ttl <= now` as "does not exist".
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from ..clock import Clock
from . import Condition, ConditionFailed, Item

LISTABLE = {
    "scim_users",
    "scim_groups",
    "audit",
    "deadletters",
    "activity",
    "metrics",
    "sessions_by_user",
}
RESERVED = {"pk", "sk", "ttl"}


def to_dynamo(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        return Decimal(repr(value))
    if isinstance(value, dict):
        return {k: to_dynamo(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_dynamo(v) for v in value]
    return value


def from_dynamo(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: from_dynamo(v) for k, v in value.items()}
    if isinstance(value, list):
        return [from_dynamo(v) for v in value]
    return value


class DynamoStore:
    def __init__(self, table_name: str, clock: Clock | None = None, resource=None):
        import boto3

        self.clock = clock or Clock()
        self.resource = resource or boto3.resource("dynamodb")
        self.table = self.resource.Table(table_name)
        self.client = self.table.meta.client

    # --- keys -------------------------------------------------------------------------------

    @staticmethod
    def _key(table: str, key: str) -> dict:
        if table in LISTABLE:
            return {"pk": table, "sk": key}
        return {"pk": f"{table}#{key}", "sk": "-"}

    def _clean(self, raw: dict | None) -> Item | None:
        if raw is None:
            return None
        if "ttl" in raw and float(raw["ttl"]) <= self.clock.now():
            return None
        return {k: from_dynamo(v) for k, v in raw.items() if k not in RESERVED}

    # --- conditions -------------------------------------------------------------------------

    def _condition(
        self, conditions: list[Condition] | None, names: dict, values: dict
    ) -> str | None:
        if not conditions:
            return None
        parts = []
        alive = "(attribute_not_exists(#ttl) OR #ttl > :now)"
        for i, cond in enumerate(conditions):
            op = cond[0]
            if op == "not_exists":
                parts.append("(attribute_not_exists(pk) OR #ttl <= :now)")
                continue
            if op == "exists":
                parts.append(f"(attribute_exists(pk) AND {alive})")
                continue
            attr, value = cond[1], cond[2]
            n, v = f"#c{i}", f":c{i}"
            names[n] = attr
            values[v] = to_dynamo(value)
            if op == "eq":
                parts.append(f"({n} = {v} AND {alive})")
            elif op == "ne":
                parts.append(f"(attribute_not_exists({n}) OR {n} <> {v})")
            elif op == "lt_or_missing":
                parts.append(f"(attribute_not_exists({n}) OR {n} < {v})")
            elif op == "le":
                parts.append(f"({n} <= {v})")
            else:
                raise ValueError(f"unknown condition {op}")
        expr = " AND ".join(parts)
        if "#ttl" in expr:  # DynamoDB rejects unused placeholders
            names["#ttl"] = "ttl"
            values[":now"] = to_dynamo(self.clock.now())
        return expr

    def _failed(self, exc, table: str, key: str) -> ConditionFailed:
        old = exc.response.get("Item")
        current = None
        if old:
            from boto3.dynamodb.types import TypeDeserializer

            des = TypeDeserializer()
            current = self._clean({k: des.deserialize(v) for k, v in old.items()})
        return ConditionFailed(table, key, current)

    @staticmethod
    def _is_condition_failure(exc) -> bool:
        return exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"

    # --- operations -------------------------------------------------------------------------

    def get(self, table: str, key: str) -> Item | None:
        resp = self.table.get_item(Key=self._key(table, key), ConsistentRead=True)
        return self._clean(resp.get("Item"))

    def put(
        self,
        table: str,
        key: str,
        item: Item,
        conditions: list[Condition] | None = None,
        ttl: float | None = None,
    ) -> None:
        from botocore.exceptions import ClientError

        body = {**to_dynamo(item), **self._key(table, key)}
        if ttl is not None:
            body["ttl"] = int(ttl)
        names: dict = {}
        values: dict = {}
        kwargs: dict = {"Item": body}
        expr = self._condition(conditions, names, values)
        if expr:
            kwargs.update(
                ConditionExpression=expr,
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ReturnValuesOnConditionCheckFailure="ALL_OLD",
            )
        try:
            self.table.put_item(**kwargs)
        except ClientError as exc:
            if self._is_condition_failure(exc):
                raise self._failed(exc, table, key) from None
            raise

    def update(
        self,
        table: str,
        key: str,
        changes: Item,
        conditions: list[Condition] | None = None,
        remove: list[str] | None = None,
        ttl: float | None = None,
    ) -> Item:
        from botocore.exceptions import ClientError

        names: dict = {}
        values: dict = {}
        sets, removes = [], []
        for i, (attr, value) in enumerate(changes.items()):
            names[f"#s{i}"] = attr
            values[f":s{i}"] = to_dynamo(value)
            sets.append(f"#s{i} = :s{i}")
        if ttl is not None:
            names["#ttlset"] = "ttl"
            values[":ttlset"] = int(ttl)
            sets.append("#ttlset = :ttlset")
        for i, attr in enumerate(remove or []):
            names[f"#r{i}"] = attr
            removes.append(f"#r{i}")
        expr = ""
        if sets:
            expr += "SET " + ", ".join(sets)
        if removes:
            expr += " REMOVE " + ", ".join(removes)
        cond = self._condition(conditions, names, values)
        kwargs: dict = {
            "Key": self._key(table, key),
            "UpdateExpression": expr.strip(),
            "ExpressionAttributeNames": names,
            "ReturnValues": "ALL_NEW",
        }
        if values:
            kwargs["ExpressionAttributeValues"] = values
        if cond:
            kwargs["ConditionExpression"] = cond
            kwargs["ReturnValuesOnConditionCheckFailure"] = "ALL_OLD"
        try:
            resp = self.table.update_item(**kwargs)
        except ClientError as exc:
            if self._is_condition_failure(exc):
                raise self._failed(exc, table, key) from None
            raise
        return self._clean(resp.get("Attributes")) or {}

    def delete(self, table: str, key: str, conditions: list[Condition] | None = None) -> None:
        from botocore.exceptions import ClientError

        names: dict = {}
        values: dict = {}
        kwargs: dict = {"Key": self._key(table, key)}
        expr = self._condition(conditions, names, values)
        if expr:
            kwargs.update(
                ConditionExpression=expr,
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
        try:
            self.table.delete_item(**kwargs)
        except ClientError as exc:
            if self._is_condition_failure(exc):
                raise ConditionFailed(table, key) from None
            raise

    def increment(self, table: str, key: str, attr: str, amount: int = 1) -> int:
        resp = self.table.update_item(
            Key=self._key(table, key),
            UpdateExpression="ADD #a :n",
            ExpressionAttributeNames={"#a": attr},
            ExpressionAttributeValues={":n": amount},
            ReturnValues="UPDATED_NEW",
        )
        return int(resp["Attributes"][attr])

    def list(
        self, table: str, prefix: str = "", limit: int = 1000, reverse: bool = False
    ) -> list[tuple[str, Item]]:
        if table not in LISTABLE:
            raise ValueError(f"{table} is not a listable table")
        from boto3.dynamodb.conditions import Key

        cond = Key("pk").eq(table)
        if prefix:
            cond = cond & Key("sk").begins_with(prefix)
        out: list[tuple[str, Item]] = []
        kwargs: dict = {
            "KeyConditionExpression": cond,
            "ScanIndexForward": not reverse,
            "ConsistentRead": True,
        }
        while len(out) < limit:
            resp = self.table.query(**kwargs)
            for raw in resp.get("Items", []):
                item = self._clean(raw)
                if item is not None:
                    out.append((raw["sk"], item))
            if "LastEvaluatedKey" not in resp:
                break
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        return out[:limit]


def create_table(resource, name: str) -> None:
    """Used by tests and the local stack; production creates the table from infra/template.yaml."""
    resource.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
