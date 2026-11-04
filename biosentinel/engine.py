"""Query engine used by the forensic auditor: every cited SQL query runs against the local DuckDB store."""
from __future__ import annotations
from .config import Config
from .store import Store


class DuckEngine:
    def __init__(self, store: Store):
        self.store = store
        self.tables = dict(Store.tables)
        self.name = "duckdb"

    def query(self, sql: str, params=()):
        return self.store.query(sql, params)


def make_engine(cfg: Config, store: Store):
    return DuckEngine(store)