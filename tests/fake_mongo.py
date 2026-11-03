"""Minimal in-memory Mongo-compatible store for deterministic API tests."""

from copy import deepcopy

from bson import ObjectId


def _matches(document: dict, query: dict) -> bool:
    for key, expected in query.items():
        actual = document.get(key)
        if isinstance(expected, dict):
            for operator, value in expected.items():
                if operator == "$gte" and not (actual is not None and actual >= value):
                    return False
                if operator == "$lte" and not (actual is not None and actual <= value):
                    return False
        elif actual != expected:
            return False
    return True


class Cursor(list):
    def sort(self, key: str, direction: int = 1):
        return Cursor(sorted(self, key=lambda item: item.get(key), reverse=direction < 0))


class Result:
    def __init__(self, inserted_id=None, matched_count=0):
        self.inserted_id = inserted_id
        self.matched_count = matched_count


class Collection:
    def __init__(self):
        self.documents = []

    def create_index(self, *_args, **_kwargs):
        return "index"

    def insert_one(self, document):
        item = deepcopy(document)
        item.setdefault("_id", ObjectId())
        self.documents.append(item)
        return Result(inserted_id=item["_id"])

    def find_one(self, query=None):
        for item in self.documents:
            if _matches(item, query or {}):
                return deepcopy(item)
        return None

    def find(self, query=None):
        return Cursor(deepcopy(item) for item in self.documents if _matches(item, query or {}))

    def update_one(self, query, update):
        for item in self.documents:
            if _matches(item, query):
                item.update(deepcopy(update.get("$set", {})))
                return Result(matched_count=1)
        return Result()

    def delete_many(self, query):
        before = len(self.documents)
        self.documents = [item for item in self.documents if not _matches(item, query)]
        return Result(matched_count=before - len(self.documents))


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
