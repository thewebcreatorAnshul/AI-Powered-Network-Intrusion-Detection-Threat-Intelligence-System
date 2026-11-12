"""Minimal in-memory Mongo-compatible store for deterministic API tests."""

from copy import deepcopy
from threading import RLock

from bson import ObjectId
from pymongo.errors import DuplicateKeyError


def _path_values(document: dict, dotted_key: str) -> list:
    current = [document]
    for part in dotted_key.split("."):
        following = []
        for value in current:
            values = value if isinstance(value, list) else [value]
            for item in values:
                if isinstance(item, dict) and part in item:
                    following.append(item[part])
        current = following
    return current


def _matches(document: dict, query: dict) -> bool:
    for key, expected in query.items():
        if key == "$or":
            if not any(_matches(document, clause) for clause in expected):
                return False
            continue
        if isinstance(expected, dict) and "$elemMatch" in expected:
            actual = document.get(key, [])
            if not isinstance(actual, list) or not any(
                _matches(item, expected["$elemMatch"]) for item in actual
            ):
                return False
            continue
        values = _path_values(document, key)
        actual = values[0] if len(values) == 1 else values
        if isinstance(expected, dict):
            for operator, value in expected.items():
                if operator == "$ne" and value in values:
                    return False
                if operator == "$gte" and not any(item is not None and item >= value for item in values):
                    return False
                if operator == "$lte" and not any(item is not None and item <= value for item in values):
                    return False
                if operator == "$lt" and not any(item is not None and item < value for item in values):
                    return False
                if operator == "$gt" and not any(item is not None and item > value for item in values):
                    return False
        elif expected not in values:
            return False
    return True


def _set_path(document: dict, dotted_key: str, value, query: dict) -> None:
    parts = dotted_key.split(".")
    if "$" in parts:
        array_name = parts[0]
        match_key = f"{array_name}.dedupe_key"
        dedupe_key = query.get(match_key)
        array = document.get(array_name, [])
        for item in array:
            if item.get("dedupe_key") == dedupe_key:
                target = item
                for part in parts[2:-1]:
                    target = target.setdefault(part, {})
                target[parts[-1]] = deepcopy(value)
                return
        return
    target = document
    for part in parts[:-1]:
        target = target.setdefault(part, {})
    target[parts[-1]] = deepcopy(value)


def _apply_update(document: dict, update: dict, query: dict) -> None:
    for key, value in update.get("$set", {}).items():
        _set_path(document, key, value, query)
    for key, value in update.get("$push", {}).items():
        document.setdefault(key, []).append(deepcopy(value))


class Cursor(list):
    def sort(self, key: str, direction: int = 1):
        return Cursor(sorted(self, key=lambda item: item.get(key), reverse=direction < 0))


class Result:
    def __init__(self, inserted_id=None, matched_count=0, upserted_id=None):
        self.inserted_id = inserted_id
        self.matched_count = matched_count
        self.upserted_id = upserted_id


class Collection:
    def __init__(self):
        self.documents = []
        self._lock = RLock()
        self.unique_indexes = []

    def create_index(self, keys, *, unique=False, sparse=False, **_kwargs):
        if unique:
            fields = (keys,) if isinstance(keys, str) else tuple(field for field, _direction in keys)
            self.unique_indexes.append((fields, unique, sparse))
        return "index"

    def _check_unique(self, document, excluding_id=None):
        for fields, _unique, sparse in self.unique_indexes:
            value = tuple(document.get(field) for field in fields)
            if sparse and all(field not in document for field in fields):
                continue
            for existing in self.documents:
                existing_value = tuple(existing.get(field) for field in fields)
                if existing.get("_id") != excluding_id and existing_value == value:
                    raise DuplicateKeyError(f"duplicate value for {fields}")

    def insert_one(self, document):
        with self._lock:
            item = deepcopy(document)
            item.setdefault("_id", ObjectId())
            self._check_unique(item)
            self.documents.append(item)
            return Result(inserted_id=item["_id"])

    def find_one(self, query=None):
        for item in self.documents:
            if _matches(item, query or {}):
                return deepcopy(item)
        return None

    def find(self, query=None):
        return Cursor(deepcopy(item) for item in self.documents if _matches(item, query or {}))

    def update_one(self, query, update, upsert=False):
        with self._lock:
            for item in self.documents:
                if _matches(item, query):
                    candidate = deepcopy(item)
                    _apply_update(candidate, update, query)
                    self._check_unique(candidate, excluding_id=item.get("_id"))
                    item.clear()
                    item.update(candidate)
                    return Result(matched_count=1)
            if upsert:
                item = {key: value for key, value in query.items() if not key.startswith("$") and not isinstance(value, dict)}
                item.update(deepcopy(update.get("$setOnInsert", {})))
                _apply_update(item, update, query)
                item.setdefault("_id", ObjectId())
                self._check_unique(item)
                self.documents.append(item)
                return Result(upserted_id=item["_id"])
        return Result()

    def find_one_and_update(self, query, update, return_document=None):
        with self._lock:
            for item in self.documents:
                if _matches(item, query):
                    _apply_update(item, update, query)
                    return deepcopy(item)
        return None

    def delete_many(self, query):
        before = len(self.documents)
        self.documents = [item for item in self.documents if not _matches(item, query)]
        return Result(matched_count=before - len(self.documents))

    def delete_one(self, query):
        with self._lock:
            for index, item in enumerate(self.documents):
                if _matches(item, query):
                    del self.documents[index]
                    return Result(matched_count=1)
        return Result()


class Database:
    def __init__(self):
        self.collections = {}

    def __getitem__(self, name):
        return self.collections.setdefault(name, Collection())

    def command(self, *_args, **_kwargs):
        return {"ok": 1}


class Client:
    def __init__(self):
        self.databases = {}
        self.admin = self

    def __getitem__(self, name):
        return self.databases.setdefault(name, Database())

    def command(self, *_args, **_kwargs):
        return {"ok": 1}

    def close(self):
        return None
