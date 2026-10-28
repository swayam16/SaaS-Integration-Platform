"""Thread-safe in-memory store with the same conditional-write semantics as DynamoDB."""

from __future__ import annotations

import copy
import threading
from collections import defaultdict

from ..clock import Clock
from . import Condition, ConditionFailed, Item, check


class MemoryStore:
    def __init__(self, clock: Clock | None = None):
        self._data: dict[str, dict[str, Item]] = defaultdict(dict)
        self._lock = threading.RLock()
        self.clock = clock or Clock()
        self.writes = 0
        self.condition_failures = 0

    def _live(self, table: str, key: str) -> Item | None:
        item = self._data[table].get(key)
        if item is not None and "_ttl" in item and item["_ttl"] <= self.clock.now():
            del self._data[table][key]
            return None
        return item

    def get(self, table: str, key: str) -> Item | None:
        with self._lock:
            item = self._live(table, key)
            return (
                None
                if item is None
                else {k: v for k, v in copy.deepcopy(item).items() if k != "_ttl"}
            )

    def put(
        self,
        table: str,
        key: str,
        item: Item,
        conditions: list[Condition] | None = None,
        ttl: float | None = None,
    ) -> None:
        with self._lock:
            current = self._live(table, key)
            if not check(conditions, current):
                self.condition_failures += 1
                raise ConditionFailed(table, key, copy.deepcopy(current))
            new = copy.deepcopy(item)
            if ttl is not None:
                new["_ttl"] = ttl
            self._data[table][key] = new
            self.writes += 1

    def update(
        self,
        table: str,
        key: str,
        changes: Item,
        conditions: list[Condition] | None = None,
        remove: list[str] | None = None,
        ttl: float | None = None,
    ) -> Item:
        with self._lock:
            current = self._live(table, key)
            if not check(conditions, current):
                self.condition_failures += 1
                raise ConditionFailed(table, key, copy.deepcopy(current))
            new = copy.deepcopy(current) if current else {}
            new.update(copy.deepcopy(changes))
            for attr in remove or []:
                new.pop(attr, None)
            if ttl is not None:
                new["_ttl"] = ttl
            self._data[table][key] = new
            self.writes += 1
            return {k: v for k, v in copy.deepcopy(new).items() if k != "_ttl"}

    def delete(self, table: str, key: str, conditions: list[Condition] | None = None) -> None:
        with self._lock:
            current = self._live(table, key)
            if not check(conditions, current):
                self.condition_failures += 1
                raise ConditionFailed(table, key, copy.deepcopy(current))
            self._data[table].pop(key, None)
            self.writes += 1

    def increment(self, table: str, key: str, attr: str, amount: int = 1) -> int:
        with self._lock:
            item = self._live(table, key) or {}
            item[attr] = int(item.get(attr, 0)) + amount
            self._data[table][key] = item
            self.writes += 1
            return item[attr]

    def list(
        self, table: str, prefix: str = "", limit: int = 1000, reverse: bool = False
    ) -> list[tuple[str, Item]]:
        with self._lock:
            keys = sorted(
                (k for k in list(self._data[table]) if k.startswith(prefix)), reverse=reverse
            )
            out = []
            for k in keys:
                item = self._live(table, k)
                if item is not None:
                    out.append((k, {a: v for a, v in copy.deepcopy(item).items() if a != "_ttl"}))
                if len(out) >= limit:
                    break
            return out

    def count(self, table: str) -> int:
        with self._lock:
            return len(self._data[table])
