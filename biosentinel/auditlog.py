"""Hash-chained audit log: every record stores the hash of the previous one.
Editing, deleting or reordering any earlier record breaks verification from that point on.
This gives TAMPER EVIDENCE only. A privileged attacker who can rewrite the whole chain (or the
head hash you keep elsewhere) can still forge it. Publish the head hash somewhere you trust."""
from __future__ import annotations
import hashlib
import json
import threading
import time

GENESIS = "0" * 64


def _digest(body: dict) -> str:
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | None = None):
        self.entries: list[dict] = []
        self.path = path or None
        self._lock = threading.Lock()

    def append(self, record: dict) -> dict:
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else GENESIS
            body = {"seq": len(self.entries), "ts": round(time.time(), 3), "prev": prev, "record": record}
            entry = {**body, "hash": _digest(body)}
            self.entries.append(entry)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
            return entry

    @staticmethod
    def verify_entries(entries: list[dict]) -> tuple[bool, int | None]:
        """(ok, index of first bad entry)."""
        prev = GENESIS
        for i, e in enumerate(entries):
            body = {"seq": e.get("seq"), "ts": e.get("ts"), "prev": e.get("prev"), "record": e.get("record")}
            if e.get("seq") != i or e.get("prev") != prev or e.get("hash") != _digest(body):
                return False, i
            prev = e["hash"]
        return True, None

    def verify(self) -> tuple[bool, int | None]:
        with self._lock:
            return self.verify_entries(list(self.entries))

    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS