"""Local telemetry store (DuckDB)."""
from __future__ import annotations
import threading
from pathlib import Path
import duckdb

DDL = [
    """CREATE TABLE IF NOT EXISTS agent_events (
        agent_id VARCHAR, step INTEGER, length INTEGER, entropy DOUBLE, compression DOUBLE,
        encoded DOUBLE, surprisal DOUBLE, secret_hits INTEGER, inj_hits INTEGER,
        obfusc_hits INTEGER, snippet VARCHAR)""",
    """CREATE TABLE IF NOT EXISTS tool_calls (
        agent_id VARCHAR, step INTEGER, tool VARCHAR, destination VARCHAR,
        destination_external INTEGER, payload_len INTEGER)""",
    """CREATE TABLE IF NOT EXISTS env_telemetry (
        agent_id VARCHAR, step INTEGER, cpu DOUBLE, err_rate DOUBLE, latency_ms DOUBLE,
        volatility DOUBLE)""",
    """CREATE TABLE IF NOT EXISTS detections (
        agent_id VARCHAR, step INTEGER, score DOUBLE, cusum DOUBLE, multiplier DOUBLE,
        state VARCHAR, signals VARCHAR)""",
    """CREATE TABLE IF NOT EXISTS quarantine_log (
        agent_id VARCHAR, step INTEGER, reason VARCHAR)""",
]


class Store:
    tables = {"events": "agent_events", "tools": "tool_calls", "env": "env_telemetry",
              "det": "detections", "quar": "quarantine_log"}

    def __init__(self, path: str = ":memory:"):
        self._lock = threading.Lock()
        self.con = duckdb.connect(path)
        for stmt in DDL:
            self.con.execute(stmt)

    def insert(self, table: str, row: dict) -> None:
        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        with self._lock:
            self.con.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", list(row.values()))

    def query(self, sql: str, params=()) -> list[dict]:
        with self._lock:
            cur = self.con.execute(sql, list(params))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def export_csv(self, outdir: str) -> list[str]:
        """Dump the tables as CSV files."""
        Path(outdir).mkdir(parents=True, exist_ok=True)
        out = []
        with self._lock:
            for t in self.tables.values():
                p = str(Path(outdir) / f"{t}.csv")
                self.con.execute(f"COPY {t} TO '{p}' (HEADER, DELIMITER ',')")
                out.append(p)
        return out